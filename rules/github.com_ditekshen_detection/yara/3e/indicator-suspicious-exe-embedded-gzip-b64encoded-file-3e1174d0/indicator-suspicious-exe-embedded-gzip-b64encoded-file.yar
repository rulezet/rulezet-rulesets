rule INDICATOR_SUSPICIOUS_EXE_Embedded_Gzip_B64Encoded_File {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing bas64 encoded gzip files"
    strings:
        $s1 = "H4sIAAAAAAA" ascii wide
        $s2 = "AAAAAAAIs4H" ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}