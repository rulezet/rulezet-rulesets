rule _20160921_e07d4e2b80172d933515ba35e18c07eb_20160921_e67c85fc609b_3158 {
  meta:
    description = "datamaliciousorder - from files 20160921_e07d4e2b80172d933515ba35e18c07eb.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1 = "Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2 = "rn \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s3 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s4 = "return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s5 = "Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s6 = "turn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s7 = "rn \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}