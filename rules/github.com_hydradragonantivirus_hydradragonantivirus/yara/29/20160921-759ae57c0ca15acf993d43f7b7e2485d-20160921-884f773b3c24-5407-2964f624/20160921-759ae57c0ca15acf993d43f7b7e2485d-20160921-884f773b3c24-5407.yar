rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_884f773b3c24_5407 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retur" ascii
    $s2 = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s3 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"" ascii
    $s4 = "urn \"Ai\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s5 = "ion fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}