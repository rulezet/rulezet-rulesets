rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_7f6803f2f6f6_4194 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash3       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"
    hash4       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){retu" ascii
    $s2 = "ction fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3 = "\"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(func" ascii
    $s4 = "k(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";" ascii
    $s5 = "c\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}