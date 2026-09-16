rule _20160921_ae190d4c26ff954cee57fde04839fdcd_20160921_ef5539a74fa9_4023 {
  meta:
    description = "datamaliciousorder - from files 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = "turn \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "k(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "rn \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s6 = "function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}