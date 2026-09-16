rule INDICATOR_KB_GoBuildID_QnapCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"XcBqbQohm7UevdYNABvs/2RcJz1616naXSRu2xvTX/b6F3Jt1-5WAIexSyzeun/MpHqs5fJA5G2D9gVuUCe\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}