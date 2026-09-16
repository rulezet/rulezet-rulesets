rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_03b650867a39_3192 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash3       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash4       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s2 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s3 = "TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(functi" ascii
    $s4 = "{return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})" ascii
    $s5 = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s6 = "return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}