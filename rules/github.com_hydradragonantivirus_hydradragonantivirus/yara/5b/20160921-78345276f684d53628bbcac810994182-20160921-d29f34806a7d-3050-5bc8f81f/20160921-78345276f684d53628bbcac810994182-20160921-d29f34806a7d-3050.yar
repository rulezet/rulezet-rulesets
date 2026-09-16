rule _20160921_78345276f684d53628bbcac810994182_20160921_d29f34806a7d_3050 {
  meta:
    description = "datamaliciousorder - from files 20160921_78345276f684d53628bbcac810994182.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Et\";})(),(function fuck(" ascii
    $s2 = "ion fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s3 = "(function fuck(){return \"Nm\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){r" ascii
    $s4 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s5 = "\"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s6 = "tion fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return" ascii
    $s7 = "eturn \"Vf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}