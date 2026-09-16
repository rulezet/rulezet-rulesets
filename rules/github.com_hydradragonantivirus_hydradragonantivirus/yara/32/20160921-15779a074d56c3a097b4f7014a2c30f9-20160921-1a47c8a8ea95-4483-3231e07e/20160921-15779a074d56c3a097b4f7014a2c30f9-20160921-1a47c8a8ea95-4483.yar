rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_1a47c8a8ea95_4483 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"

  strings:
    $s1 = "rn \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s2 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s3 = " \"Zy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s4 = "fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UX" ascii
    $s5 = "n \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}