rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_4876 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"

  strings:
    $s1 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s2 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){r" ascii
    $s3 = "(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";}" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0" ascii
    $s5 = "return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}