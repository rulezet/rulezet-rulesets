rule _20160921_510713862e5c8c05841e5272407127f3_20160921_a160e4a38580_127 {
  meta:
    description = "datamaliciousorder - from files 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash2       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"

  strings:
    $s1  = "return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})()," ascii
    $s2  = "(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s3  = "uck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\"" ascii
    $s4  = "tion fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s5  = " fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai" ascii
    $s6  = "n \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(fu" ascii
    $s7  = "k(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\"" ascii
    $s8  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s9  = "rn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s10 = "){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})" ascii
    $s11 = ")(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck()" ascii
    $s12 = "OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MOj\";})(),(funct" ascii
    $s13 = "){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})" ascii
    $s14 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s15 = "n fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s16 = "ck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\"" ascii
    $s17 = "n \"GJx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s18 = " \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fun" ascii
    $s19 = "(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){" ascii
    $s20 = "\"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}