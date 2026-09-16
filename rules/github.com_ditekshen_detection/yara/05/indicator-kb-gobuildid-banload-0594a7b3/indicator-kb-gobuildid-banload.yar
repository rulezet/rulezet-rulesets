rule INDICATOR_KB_GoBuildID_Banload {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"a3629ee6ab610a57f242f59a3dd5e5f6de73da40\"" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}