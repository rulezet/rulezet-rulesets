rule _20160921_ef5539a74fa92cc432f92987e238b0be_20160921_f575ae0885e7_285 {
  meta:
    description = "datamaliciousorder - from files 20160921_ef5539a74fa92cc432f92987e238b0be.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"
    hash2       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2  = "Kv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s3  = "nction fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s4  = "{return \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s5  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s6  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s7  = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function " ascii
    $s8  = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(" ascii
    $s9  = "t\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"YQt\";})(),(function" ascii
    $s10 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PD" ascii
    $s11 = "uck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IR" ascii
    $s12 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s13 = "(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";" ascii
    $s14 = "x\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s15 = "n \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s16 = "turn \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s17 = "n \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s18 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function" ascii
    $s19 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s20 = "turn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}