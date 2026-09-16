rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_567 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash4       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1  = " \"Oh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s2  = "(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";}" ascii
    $s3  = "ck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";" ascii
    $s4  = "fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo" ascii
    $s5  = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s6  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s7  = "n fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NK" ascii
    $s8  = "ck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu" ascii
    $s9  = "rn \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(fu" ascii
    $s10 = "{return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s11 = "ck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py" ascii
    $s12 = "rn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(fu" ascii
    $s13 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s14 = "\"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s15 = "),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s16 = "uck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py" ascii
    $s17 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"L" ascii
    $s18 = "uck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IRn" ascii
    $s19 = "ion fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s20 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}