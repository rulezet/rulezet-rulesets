rule _20160921_91734b00fd54cd3dd10c5f20c35d7864_20160921_d414cec9501c_5541 {
  meta:
    description = "datamaliciousorder - from files 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash3       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s2 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s3 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";" ascii
    $s4 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s5 = "){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}