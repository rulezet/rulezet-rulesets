rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_468b13a80ecc_305 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1  = ")(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s2  = "uck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PD" ascii
    $s3  = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"US" ascii
    $s4  = "{return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})" ascii
    $s5  = "n fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s6  = "function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s7  = "turn \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s8  = "eturn \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s9  = "n\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(function" ascii
    $s10 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s11 = "fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s12 = ";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function f" ascii
    $s13 = "urn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s14 = ";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s15 = "v\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s16 = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck()" ascii
    $s17 = "ck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii
    $s18 = "turn \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s19 = "(function fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){" ascii
    $s20 = "n \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}