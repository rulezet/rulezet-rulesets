rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_d35b8ea76f45_3892 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(function fuck()" ascii
    $s2 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s3 = "Pu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s4 = "){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";" ascii
    $s5 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii
    $s6 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}