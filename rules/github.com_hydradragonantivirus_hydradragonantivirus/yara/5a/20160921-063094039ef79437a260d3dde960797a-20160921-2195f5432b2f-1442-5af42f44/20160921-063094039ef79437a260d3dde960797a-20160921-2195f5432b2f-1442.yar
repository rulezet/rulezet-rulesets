rule _20160921_063094039ef79437a260d3dde960797a_20160921_2195f5432b2f_1442 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"

  strings:
    $s1  = "n \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2  = "eturn \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})()," ascii
    $s3  = "on fuck(){return \"EHo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s4  = "rn \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(f" ascii
    $s5  = "n fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s6  = "fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Xw" ascii
    $s7  = "return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"IOs\";})()" ascii
    $s8  = ")(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s9  = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){ret" ascii
    $s10 = "fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"J" ascii
    $s11 = "\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function " ascii
    $s12 = "function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s13 = "rn \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}