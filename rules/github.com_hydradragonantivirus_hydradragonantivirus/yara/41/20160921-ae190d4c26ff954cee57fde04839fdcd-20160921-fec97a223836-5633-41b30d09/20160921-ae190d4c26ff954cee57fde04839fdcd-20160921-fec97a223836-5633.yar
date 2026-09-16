rule _20160921_ae190d4c26ff954cee57fde04839fdcd_20160921_fec97a223836_5633 {
  meta:
    description = "datamaliciousorder - from files 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = " fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s2 = " \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s3 = "fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu" ascii
    $s4 = " \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(func" ascii
    $s5 = "nction fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}