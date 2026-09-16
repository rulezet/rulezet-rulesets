rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig {
    meta:
        author = "ditekSHen"
        description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    strings:
        $s1 = "<configSections>" ascii nocase
        $s2 = "<value>77 90" ascii nocase
    condition:
       uint32(0) == 0x6d783f3c and all of them
}