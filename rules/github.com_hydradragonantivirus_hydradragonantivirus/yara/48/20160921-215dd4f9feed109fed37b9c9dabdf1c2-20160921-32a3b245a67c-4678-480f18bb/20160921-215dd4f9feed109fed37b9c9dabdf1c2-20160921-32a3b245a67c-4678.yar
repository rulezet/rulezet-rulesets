rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_32a3b245a67c_4678 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"

  strings:
    $s1 = "urn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s2 = "ck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\"" ascii
    $s3 = "uck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\"" ascii
    $s4 = "return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s5 = "(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}