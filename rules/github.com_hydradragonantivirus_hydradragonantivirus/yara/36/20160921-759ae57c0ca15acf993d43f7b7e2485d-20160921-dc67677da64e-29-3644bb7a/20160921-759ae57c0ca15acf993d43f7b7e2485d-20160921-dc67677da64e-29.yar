rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_dc67677da64e_29 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1  = "turn \"Qh\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s2  = "(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"To\";})(),(function fuck(" ascii
    $s3  = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s4  = "(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";" ascii
    $s5  = "nction fuck(){return \"DWe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s6  = "return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})" ascii
    $s7  = "(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"LGo\";})(),(function fuck" ascii
    $s8  = "\"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(functi" ascii
    $s9  = "urn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DWe\";})(),(" ascii
    $s10 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})()," ascii
    $s11 = "Pu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function" ascii
    $s12 = "){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s13 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){re" ascii
    $s14 = "){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})" ascii
    $s15 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s16 = "\"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"RAi\";})(),(func" ascii
    $s17 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s18 = "Pu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s19 = "n fuck(){return \"Ot\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s20 = "eturn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DWe\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}