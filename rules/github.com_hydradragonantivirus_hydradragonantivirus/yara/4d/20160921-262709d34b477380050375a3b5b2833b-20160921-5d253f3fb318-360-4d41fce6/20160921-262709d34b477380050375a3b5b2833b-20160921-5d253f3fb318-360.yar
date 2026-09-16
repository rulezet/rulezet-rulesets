rule _20160921_262709d34b477380050375a3b5b2833b_20160921_5d253f3fb318_360 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"

  strings:
    $s1  = "{return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s2  = "urn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s3  = "MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(functi" ascii
    $s4  = "on fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"I" ascii
    $s5  = "uck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s6  = "(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";}" ascii
    $s7  = "Ts\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(functio" ascii
    $s8  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";}" ascii
    $s9  = "eturn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s10 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s11 = " fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"I" ascii
    $s12 = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s13 = "rn \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Ot\";})(),(fu" ascii
    $s14 = "k(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";" ascii
    $s15 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s16 = "(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";}" ascii
    $s17 = "(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";}" ascii
    $s18 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retu" ascii
    $s19 = " \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s20 = "ction fuck(){return \"CCb\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}