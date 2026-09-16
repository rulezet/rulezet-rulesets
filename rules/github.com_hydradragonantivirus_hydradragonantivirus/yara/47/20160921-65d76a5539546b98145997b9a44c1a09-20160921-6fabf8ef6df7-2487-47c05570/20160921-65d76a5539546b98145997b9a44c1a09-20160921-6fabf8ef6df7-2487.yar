rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_6fabf8ef6df7_2487 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"

  strings:
    $s1 = ",(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s2 = "tion fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s3 = "urn \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(" ascii
    $s4 = "k(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";" ascii
    $s5 = "\"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(func" ascii
    $s6 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){retu" ascii
    $s7 = "n \"MIl\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s8 = " \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}