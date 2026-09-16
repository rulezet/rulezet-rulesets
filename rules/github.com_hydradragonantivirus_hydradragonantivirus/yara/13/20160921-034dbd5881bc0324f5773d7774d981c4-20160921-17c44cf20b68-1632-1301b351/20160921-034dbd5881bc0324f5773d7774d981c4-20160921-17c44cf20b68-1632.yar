rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_1632 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash4       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"

  strings:
    $s1  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"" ascii
    $s2  = "urn \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(" ascii
    $s3  = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s4  = "fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"P" ascii
    $s5  = "rn \"Nm\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s6  = "\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s7  = "unction fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){re" ascii
    $s8  = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"N" ascii
    $s9  = "(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";}" ascii
    $s10 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(" ascii
    $s11 = "fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MB" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}