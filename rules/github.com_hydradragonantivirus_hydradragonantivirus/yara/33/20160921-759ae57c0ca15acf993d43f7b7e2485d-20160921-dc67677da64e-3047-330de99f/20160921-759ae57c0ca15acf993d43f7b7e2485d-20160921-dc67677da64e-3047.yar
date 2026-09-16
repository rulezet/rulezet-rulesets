rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_dc67677da64e_3047 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash3       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(functi" ascii
    $s2 = "ck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\"" ascii
    $s3 = "(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\"" ascii
    $s4 = "unction fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s6 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s7 = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}