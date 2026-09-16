rule _20160921_b6d1e9aee3a026c6f266b107f0b88f18_20160921_eb8df0d94f3c_1362 {
  meta:
    description = "datamaliciousorder - from files 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s2  = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck()" ascii
    $s3  = "){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";}" ascii
    $s4  = "function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s5  = ")(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck" ascii
    $s6  = "(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s7  = "\"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s8  = "tion fuck(){return \"Ug\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return " ascii
    $s9  = "TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(functi" ascii
    $s10 = "n \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s11 = "n \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s12 = "fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx" ascii
    $s13 = "n fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s14 = "turn \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})()," ascii
    $s15 = "ck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"YAv" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}