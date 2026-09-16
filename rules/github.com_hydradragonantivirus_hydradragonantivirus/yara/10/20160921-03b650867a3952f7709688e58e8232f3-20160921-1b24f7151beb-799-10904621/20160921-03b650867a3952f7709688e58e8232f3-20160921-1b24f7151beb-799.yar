rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_1b24f7151beb_799 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash3       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "ion fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s2  = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s3  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv" ascii
    $s4  = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retu" ascii
    $s5  = "(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})" ascii
    $s6  = "rn \"PDf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s7  = "n \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s8  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s9  = "eturn \"Dc\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s10 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})" ascii
    $s11 = "n \"XFd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s12 = "Qr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s13 = "eturn \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s14 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s15 = ";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s16 = "(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"We\";}" ascii
    $s17 = "{return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(" ascii
    $s18 = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fu" ascii
    $s19 = "n fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s20 = " fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IR" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}