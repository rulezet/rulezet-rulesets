rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_5cc1e2fc6d6f_457 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1  = "(function fuck(){return \"Et\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s2  = "urn \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s3  = "turn \"To\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4  = "(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";" ascii
    $s5  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return" ascii
    $s6  = "eturn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s7  = " \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s8  = " \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s9  = "uck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IP" ascii
    $s10 = "IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s11 = "ck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s12 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){ret" ascii
    $s13 = " \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s14 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s15 = "Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function" ascii
    $s16 = "urn \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s17 = "(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jh\";})" ascii
    $s18 = "return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s19 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s20 = " fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IR" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}