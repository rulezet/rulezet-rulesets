rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_3b7ec37cdbfa_1381 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash3       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "\"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s2  = ";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fu" ascii
    $s3  = ",(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s4  = "ck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq" ascii
    $s5  = "){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";}" ascii
    $s6  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return" ascii
    $s7  = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";" ascii
    $s8  = "ion fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s9  = " \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(func" ascii
    $s10 = "k(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\"" ascii
    $s11 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(" ascii
    $s12 = "y\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s13 = " \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(fun" ascii
    $s14 = "(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}