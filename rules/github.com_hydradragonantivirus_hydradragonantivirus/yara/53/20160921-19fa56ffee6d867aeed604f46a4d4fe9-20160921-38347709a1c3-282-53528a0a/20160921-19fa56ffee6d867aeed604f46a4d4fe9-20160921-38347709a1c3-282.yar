rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_38347709a1c3_282 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1  = "Pu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function" ascii
    $s2  = "rn \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3  = "tion fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s4  = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(" ascii
    $s5  = "n \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s6  = "uck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq" ascii
    $s7  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s8  = "(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s9  = " fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s10 = "\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function f" ascii
    $s11 = "fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"U" ascii
    $s12 = "Oe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s13 = "Pu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(functio" ascii
    $s14 = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s15 = "n \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s16 = "n fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s17 = "rn \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s18 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s19 = "(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s20 = "function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}