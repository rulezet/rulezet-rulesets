rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_794 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"

  strings:
    $s1  = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = "){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})" ascii
    $s3  = "turn \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(" ascii
    $s4  = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s5  = "eturn \"Wo0\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s6  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";" ascii
    $s7  = "n \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s8  = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return" ascii
    $s9  = " fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IP" ascii
    $s10 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NK" ascii
    $s11 = "\"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s12 = "){return \"Ar\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})" ascii
    $s13 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s14 = "turn \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(" ascii
    $s15 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s16 = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s17 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ar" ascii
    $s18 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s19 = "(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";}" ascii
    $s20 = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Xg\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}