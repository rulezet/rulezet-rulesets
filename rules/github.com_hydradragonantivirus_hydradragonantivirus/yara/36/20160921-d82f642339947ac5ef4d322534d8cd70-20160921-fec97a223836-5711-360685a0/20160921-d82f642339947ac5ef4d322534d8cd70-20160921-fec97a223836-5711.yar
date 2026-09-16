rule _20160921_d82f642339947ac5ef4d322534d8cd70_20160921_fec97a223836_5711 {
  meta:
    description = "datamaliciousorder - from files 20160921_d82f642339947ac5ef4d322534d8cd70.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "rn \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s2 = "rn \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s3 = "turn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})()" ascii
    $s4 = ")(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(" ascii
    $s5 = "o\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"XFd\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}