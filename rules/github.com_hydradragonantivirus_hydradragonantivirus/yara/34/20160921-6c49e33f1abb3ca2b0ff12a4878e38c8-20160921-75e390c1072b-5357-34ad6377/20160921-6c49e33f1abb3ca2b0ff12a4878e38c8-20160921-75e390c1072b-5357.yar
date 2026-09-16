rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_75e390c1072b_5357 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){ret" ascii
    $s2 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){r" ascii
    $s3 = "n \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s4 = "n fuck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo" ascii
    $s5 = "ck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}