rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_75e390c1072b_5359 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash4       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s2 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})()" ascii
    $s3 = " \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s4 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"F" ascii
    $s5 = "on fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}