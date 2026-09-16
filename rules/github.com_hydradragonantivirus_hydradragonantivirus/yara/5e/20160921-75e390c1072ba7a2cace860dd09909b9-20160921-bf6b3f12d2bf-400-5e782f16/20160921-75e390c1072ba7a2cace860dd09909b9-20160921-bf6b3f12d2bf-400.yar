rule _20160921_75e390c1072ba7a2cace860dd09909b9_20160921_bf6b3f12d2bf_400 {
  meta:
    description = "datamaliciousorder - from files 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash2       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"
    hash3       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1  = "turn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2  = "n \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s3  = "rn \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s4  = "turn \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})()," ascii
    $s5  = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s6  = " \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s7  = "function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s8  = "function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s9  = "(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})" ascii
    $s10 = "uck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn" ascii
    $s11 = "s\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s12 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s13 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s14 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s15 = "turn \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s16 = "Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s17 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s18 = "\"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(funct" ascii
    $s19 = "(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";}" ascii
    $s20 = "rn \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}