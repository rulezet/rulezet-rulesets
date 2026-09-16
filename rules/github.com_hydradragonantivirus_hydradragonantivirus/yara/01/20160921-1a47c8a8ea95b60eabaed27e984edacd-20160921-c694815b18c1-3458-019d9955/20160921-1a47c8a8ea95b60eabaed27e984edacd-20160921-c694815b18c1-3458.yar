rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_c694815b18c1_3458 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_c694815b18c140f34c0f79f86106d901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"

  strings:
    $s1 = "UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(funct" ascii
    $s2 = "rn \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s3 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s4 = "fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){re" ascii
    $s6 = " fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}