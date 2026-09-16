rule _20160921_aa7387335b72c30a3b2a33711bac8907_20160921_e01bb59eb24d_3111 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash2       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = "(){return \"MBg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s2 = "){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(" ascii
    $s3 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s4 = " fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MO" ascii
    $s5 = "\"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s6 = "),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s7 = "eturn \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}