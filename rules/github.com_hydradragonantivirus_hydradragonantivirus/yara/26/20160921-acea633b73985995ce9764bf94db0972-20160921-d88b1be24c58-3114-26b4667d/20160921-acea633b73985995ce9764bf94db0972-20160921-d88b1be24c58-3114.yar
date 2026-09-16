rule _20160921_acea633b73985995ce9764bf94db0972_20160921_d88b1be24c58_3114 {
  meta:
    description = "datamaliciousorder - from files 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_d88b1be24c583b3513de141e173a825f.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash2       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"
    hash3       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){re" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = ")(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s4 = "YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(functi" ascii
    $s5 = " fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"M" ascii
    $s6 = "(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s7 = " fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}