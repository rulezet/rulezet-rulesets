rule INDICATOR_KB_GoBuildID_Zebrocy {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"l6RAKXh3Wg1yzn63nita/b2_Y0DGY05NFWuZ_4gUT/H91sCRktnyyYVzECfvvA/l8f-yII0L_miSjIe-VQu\"" ascii
        $s2 = "Go build ID: \"fiGGvLVFcvIhuJsSaail/jLt9TEPQiusg7IpRkp4H/hlcoXZIfsl1D4521LqEL/yL8dN86mCNc39WqQTgGn\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}