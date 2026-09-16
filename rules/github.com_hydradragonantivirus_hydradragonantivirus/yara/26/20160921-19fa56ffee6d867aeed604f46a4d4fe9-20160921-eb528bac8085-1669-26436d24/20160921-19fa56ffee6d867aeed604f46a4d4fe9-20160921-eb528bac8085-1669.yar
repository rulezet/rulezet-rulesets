rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_eb528bac8085_1669 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"
    hash3       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1  = ",(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){" ascii
    $s2  = " fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TT" ascii
    $s3  = "n \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(func" ascii
    $s4  = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function" ascii
    $s5  = "(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";" ascii
    $s6  = "IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(functi" ascii
    $s7  = "LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii
    $s8  = "unction fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s9  = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(functi" ascii
    $s10 = "{return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Cd\";})()" ascii
    $s11 = "n \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}