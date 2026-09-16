rule _20160921_93920c7f8d8dcef0135d270226e913f5_20160921_d35b8ea76f45_5554 {
  meta:
    description = "datamaliciousorder - from files 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(" ascii
    $s2 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){re" ascii
    $s3 = "})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s4 = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s5 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}