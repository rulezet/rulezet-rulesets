rule _20160921_b23a0d871d76c64a3c71f0b0f52faaa8_20160921_ce3c0604d52e_1620 {
  meta:
    description = "datamaliciousorder - from files 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1  = "\"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s2  = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s3  = "return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s4  = "rn \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s5  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii
    $s6  = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s7  = "ion fuck(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s8  = ")(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fuck" ascii
    $s9  = "x\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s10 = "urn \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s11 = "(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";" ascii
    $s12 = "k(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}