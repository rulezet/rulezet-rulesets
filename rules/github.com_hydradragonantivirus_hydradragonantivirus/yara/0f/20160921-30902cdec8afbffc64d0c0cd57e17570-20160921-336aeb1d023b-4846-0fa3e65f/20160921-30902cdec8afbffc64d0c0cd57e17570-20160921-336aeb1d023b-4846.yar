rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_336aeb1d023b_4846 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash3       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"

  strings:
    $s1 = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s2 = "\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function " ascii
    $s3 = ")(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuc" ascii
    $s4 = "n fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s5 = "return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}