rule _20160921_7c5b5eaba938fa91eb6a9414212e13f9_20160921_91734b00fd54_3929 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function f" ascii
    $s2 = "return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})()" ascii
    $s3 = "n \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s4 = "eturn \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(" ascii
    $s5 = "function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retu" ascii
    $s6 = "ck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}