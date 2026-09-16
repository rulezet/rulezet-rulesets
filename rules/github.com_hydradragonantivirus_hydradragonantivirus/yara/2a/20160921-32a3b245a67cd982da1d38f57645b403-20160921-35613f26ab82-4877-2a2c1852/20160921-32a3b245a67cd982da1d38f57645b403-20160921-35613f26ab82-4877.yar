rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_4877 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash4       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash5       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash6       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NK" ascii
    $s2 = "return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s3 = "(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";" ascii
    $s4 = "b\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s5 = "Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}