rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5032 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash4       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = "Pz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(functi" ascii
    $s2 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(f" ascii
    $s3 = "ck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s4 = "fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"E" ascii
    $s5 = "ction fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}