rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_eb528bac8085_34 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1  = "){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})" ascii
    $s2  = " fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu" ascii
    $s3  = "\"MUs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s4  = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s5  = "(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){r" ascii
    $s6  = "function fuck(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s7  = "(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s8  = "{return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";}" ascii
    $s9  = "(function fuck(){return \"MIl\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){" ascii
    $s10 = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function " ascii
    $s11 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"XFd\";})(),(fun" ascii
    $s12 = "\"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s13 = "{return \"Nm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})" ascii
    $s14 = "Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s15 = "n fuck(){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"F" ascii
    $s16 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg\"" ascii
    $s17 = "i\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s18 = "return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})" ascii
    $s19 = "return \"ZWu\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s20 = "Aa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}