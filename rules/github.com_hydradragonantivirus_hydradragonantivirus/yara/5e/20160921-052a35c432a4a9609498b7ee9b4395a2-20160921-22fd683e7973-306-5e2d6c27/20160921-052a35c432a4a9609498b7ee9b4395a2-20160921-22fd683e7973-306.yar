rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_22fd683e7973_306 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_a5297a3430b731f07a8b2bd532530907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"

  strings:
    $s1  = "eturn \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s2  = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s3  = "d\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(functio" ascii
    $s4  = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s5  = "urn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s6  = "\"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s7  = "unction fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s8  = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s9  = "ion fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s10 = "rn \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s11 = "RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s12 = "n \"We\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s13 = "rn \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s14 = "Sf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(functi" ascii
    $s15 = "){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";" ascii
    $s16 = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s17 = "RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii
    $s18 = "on fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s19 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s20 = "eturn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}