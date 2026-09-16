rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_be8454f98b5a_2461 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1 = "ction fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s2 = "\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s3 = "n \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s4 = "IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(functi" ascii
    $s5 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii
    $s6 = "rn \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(f" ascii
    $s7 = "turn \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8 = "eturn \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}