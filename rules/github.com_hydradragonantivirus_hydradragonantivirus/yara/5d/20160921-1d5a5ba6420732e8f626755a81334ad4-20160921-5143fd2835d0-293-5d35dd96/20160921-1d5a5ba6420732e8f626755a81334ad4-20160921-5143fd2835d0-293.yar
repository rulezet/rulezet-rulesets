rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_293 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash3       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1  = "PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s2  = "urn \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s3  = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){re" ascii
    $s4  = "n \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s5  = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s6  = "Ts\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s7  = "function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s8  = "Nm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(functi" ascii
    $s9  = "(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\"" ascii
    $s10 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function f" ascii
    $s11 = "function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s12 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s13 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s14 = "ck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s15 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s16 = "(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";}" ascii
    $s17 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fu" ascii
    $s18 = "unction fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s19 = "\"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s20 = "(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}