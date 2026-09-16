rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_4bad0ae96eb9_376 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_9b80c329004df146d978cb7b31b22c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash3       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"

  strings:
    $s1  = "(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";" ascii
    $s2  = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s3  = "\"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Ai\";})(),(funct" ascii
    $s4  = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s5  = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s6  = "n \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(func" ascii
    $s7  = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s8  = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s9  = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s10 = "(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s11 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s12 = " fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"H" ascii
    $s13 = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s14 = "o\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s15 = "uck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai" ascii
    $s16 = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s17 = "on fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s18 = " \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s19 = "ck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Ai\"" ascii
    $s20 = "eturn \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}