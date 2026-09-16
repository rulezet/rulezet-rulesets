rule INDICATOR_SUSPICIOUS_EXE_References_PublicServiceInterface {
    meta:
        author = "ditekSHen"
        description = "Detect executables referencing public and free service interface testing and dev services as means of CnC"
    strings:
        $s1 = "mockbin.org/bin" ascii wide nocase
        $s2 = "run.mocky.io/v3" ascii wide nocase
        $s3 = "webhook.site/" ascii wide nocase
        $s4 = "devtunnels.ms/" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and 1 of them
}