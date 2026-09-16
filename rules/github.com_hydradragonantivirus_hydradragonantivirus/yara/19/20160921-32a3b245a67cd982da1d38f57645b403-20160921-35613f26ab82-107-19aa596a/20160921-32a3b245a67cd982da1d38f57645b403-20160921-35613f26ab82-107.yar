rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_107 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"

  strings:
    $s1  = "rn \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(fu" ascii
    $s2  = "\"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(func" ascii
    $s3  = ";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fu" ascii
    $s4  = "turn \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})()," ascii
    $s5  = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){retur" ascii
    $s6  = "n fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s7  = "(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s8  = "function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s9  = "k(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";" ascii
    $s10 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s11 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s12 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Av\";})(),(" ascii
    $s13 = "n fuck(){return \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s14 = "{return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(" ascii
    $s15 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s16 = " fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"E" ascii
    $s17 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s18 = "{return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})()" ascii
    $s19 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})()" ascii
    $s20 = "Aa\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}