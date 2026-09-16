rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_9b80c329004d_78 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_9b80c329004df146d978cb7b31b22c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"

  strings:
    $s1  = "n \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2  = "on fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s3  = " \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(func" ascii
    $s4  = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuc" ascii
    $s5  = "turn \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})()," ascii
    $s6  = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s7  = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s8  = "Ts\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s9  = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\";}" ascii
    $s10 = "n \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s11 = " \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s12 = "Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(functi" ascii
    $s13 = "urn \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s14 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s15 = "ction fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return" ascii
    $s16 = "TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s17 = "rn \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s18 = "return \"Zy\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s19 = "rn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s20 = "{return \"DWe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}