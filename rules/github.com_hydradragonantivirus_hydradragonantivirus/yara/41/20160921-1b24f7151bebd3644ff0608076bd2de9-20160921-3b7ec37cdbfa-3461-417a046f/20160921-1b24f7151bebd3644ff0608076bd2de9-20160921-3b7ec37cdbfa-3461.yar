rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_3b7ec37cdbfa_3461 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"

  strings:
    $s1 = " \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(functi" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){ret" ascii
    $s4 = "{return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s5 = "turn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s6 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}