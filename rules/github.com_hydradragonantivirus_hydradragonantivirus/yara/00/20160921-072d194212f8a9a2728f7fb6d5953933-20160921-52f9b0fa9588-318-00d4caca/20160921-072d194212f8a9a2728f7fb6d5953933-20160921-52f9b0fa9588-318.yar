rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_318 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash4       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1  = "rn \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fu" ascii
    $s2  = "eturn \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})()" ascii
    $s3  = "fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IP" ascii
    $s4  = "n fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"A" ascii
    $s5  = "(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";" ascii
    $s6  = "return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s7  = "ck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi" ascii
    $s8  = " fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Z" ascii
    $s9  = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s10 = "return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})()" ascii
    $s11 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s12 = "return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s13 = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s14 = "on fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s15 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s16 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s17 = "urn \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s18 = "ck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\"" ascii
    $s19 = ";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuc" ascii
    $s20 = "\"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}