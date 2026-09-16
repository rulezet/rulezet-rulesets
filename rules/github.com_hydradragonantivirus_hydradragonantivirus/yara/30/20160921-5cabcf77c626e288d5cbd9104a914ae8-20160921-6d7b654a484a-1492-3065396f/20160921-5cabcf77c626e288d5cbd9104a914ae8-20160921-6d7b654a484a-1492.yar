rule _20160921_5cabcf77c626e288d5cbd9104a914ae8_20160921_6d7b654a484a_1492 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash2       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash3       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1  = "})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck" ascii
    $s2  = "eturn \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3  = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck()" ascii
    $s4  = "rn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii
    $s5  = "uck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "turn \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s7  = "DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s8  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retur" ascii
    $s9  = "(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){re" ascii
    $s10 = ";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fu" ascii
    $s11 = "n \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s12 = "){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";" ascii
    $s13 = "Ve\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}