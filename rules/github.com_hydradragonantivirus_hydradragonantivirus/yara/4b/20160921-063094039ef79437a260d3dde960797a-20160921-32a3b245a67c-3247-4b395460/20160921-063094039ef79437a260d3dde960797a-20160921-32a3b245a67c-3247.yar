rule _20160921_063094039ef79437a260d3dde960797a_20160921_32a3b245a67c_3247 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash4       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "{return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";}" ascii
    $s2 = "turn \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s3 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){ret" ascii
    $s4 = "m\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Dc\";})(),(function" ascii
    $s5 = "k(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";" ascii
    $s6 = "rn \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}