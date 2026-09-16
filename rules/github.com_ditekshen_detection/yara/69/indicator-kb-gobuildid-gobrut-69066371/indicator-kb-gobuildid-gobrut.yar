rule INDICATOR_KB_GoBuildID_GoBrut {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in GoBrut"       
    strings:
        $s1 = "Go build ID: \"sf_2_ylcjquGBe4mQ99L/aPvdLbM2z9HfoDN3RazG/8bhYeVA67N-ifbDYCDJe/UZzCu_EFL9f10gSfO4L0\"" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}