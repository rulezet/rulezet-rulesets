rule INDICATOR_KB_GoBuildID_RanumBot {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"hOhuOA4W60aBBRoFQTDA/dl9DuLAgEcabYGK6ZT2t/ECsse3630jV_957OqqK3/ZRA_JRPFzxutK16zlEcM\"" ascii
        $s2 = "Go build ID: \"NivDrAudWE-E6xtBXeww/3pv6fDzDqt4v0YxoTkPt/8vd79TNE-9Bt38ftxf_V/_GNqnqEUsRf-WTSmn8dM\"" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}