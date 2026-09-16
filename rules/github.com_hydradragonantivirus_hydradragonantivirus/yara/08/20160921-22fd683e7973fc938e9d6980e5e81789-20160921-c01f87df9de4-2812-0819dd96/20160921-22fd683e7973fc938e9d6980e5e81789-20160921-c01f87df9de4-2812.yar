rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_c01f87df9de4_2812 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "unction fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s2 = "on fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"G" ascii
    $s3 = "d\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s4 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){re" ascii
    $s5 = "),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s6 = "{return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})()" ascii
    $s7 = "\"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}