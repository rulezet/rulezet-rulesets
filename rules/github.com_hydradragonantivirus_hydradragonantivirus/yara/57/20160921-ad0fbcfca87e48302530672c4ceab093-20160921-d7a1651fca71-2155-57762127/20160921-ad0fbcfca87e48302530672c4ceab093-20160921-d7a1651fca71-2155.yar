rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_d7a1651fca71_2155 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1 = "n fuck(){return \"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){" ascii
    $s3 = ";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Hs\";})(),(function fuc" ascii
    $s4 = "ck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe" ascii
    $s5 = " fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IR" ascii
    $s6 = "ck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";" ascii
    $s7 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){r" ascii
    $s8 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s9 = " \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}