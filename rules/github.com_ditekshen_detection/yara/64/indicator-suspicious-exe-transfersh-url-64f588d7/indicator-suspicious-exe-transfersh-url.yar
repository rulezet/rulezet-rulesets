rule INDICATOR_SUSPICIOUS_EXE_TransferSh_URL {
    meta:
        author = "ditekSHen"
        description = "Detects files referencing the transfer.sh file sharing website"
    strings:
        $s1 = "//transfer.sh/get/" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 1 of them
}