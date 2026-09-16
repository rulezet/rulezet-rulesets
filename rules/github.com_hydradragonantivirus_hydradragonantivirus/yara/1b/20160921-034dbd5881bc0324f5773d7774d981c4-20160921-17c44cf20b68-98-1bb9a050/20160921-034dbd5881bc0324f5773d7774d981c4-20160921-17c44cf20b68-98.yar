rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_98 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"

  strings:
    $s1  = "\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s2  = "})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck" ascii
    $s3  = "n \"AUx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s4  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"" ascii
    $s5  = "urn \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(" ascii
    $s6  = "urn \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(f" ascii
    $s7  = "){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})" ascii
    $s8  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s9  = "(function fuck(){return \"We\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Av\";})(),(function fuck(){ret" ascii
    $s10 = "(){return \"Jg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s11 = " fuck(){return \"DRx\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"D" ascii
    $s12 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Na\";})(),(function fuck" ascii
    $s13 = "n fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s14 = "k(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";" ascii
    $s15 = " \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(func" ascii
    $s16 = "fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"H" ascii
    $s17 = " \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s18 = "u\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s19 = " fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"I" ascii
    $s20 = "IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}