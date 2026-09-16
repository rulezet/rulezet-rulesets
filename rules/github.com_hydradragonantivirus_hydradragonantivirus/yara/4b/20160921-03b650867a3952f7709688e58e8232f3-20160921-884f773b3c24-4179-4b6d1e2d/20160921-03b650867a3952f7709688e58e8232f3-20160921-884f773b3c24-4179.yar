rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_884f773b3c24_4179 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo" ascii
    $s2 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s3 = "n \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(f" ascii
    $s4 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s5 = "rn \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}