rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_3609 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = "k(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";" ascii
    $s2 = "uck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot" ascii
    $s3 = "\"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s4 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";}" ascii
    $s5 = "{return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})()" ascii
    $s6 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}