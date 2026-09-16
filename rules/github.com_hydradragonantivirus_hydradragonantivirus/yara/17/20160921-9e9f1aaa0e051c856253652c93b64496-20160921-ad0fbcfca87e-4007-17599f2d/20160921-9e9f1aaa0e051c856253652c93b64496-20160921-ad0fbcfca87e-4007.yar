rule _20160921_9e9f1aaa0e051c856253652c93b64496_20160921_ad0fbcfca87e_4007 {
  meta:
    description = "datamaliciousorder - from files 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3 = "u\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(function" ascii
    $s4 = "\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s5 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ot\";})(" ascii
    $s6 = "),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}