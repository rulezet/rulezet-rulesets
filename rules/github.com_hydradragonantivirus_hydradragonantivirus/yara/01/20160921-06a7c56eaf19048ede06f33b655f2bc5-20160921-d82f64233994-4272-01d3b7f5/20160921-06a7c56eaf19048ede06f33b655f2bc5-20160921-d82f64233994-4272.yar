rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_d82f64233994_4272 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s2 = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s3 = "Ts\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii
    $s4 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"" ascii
    $s5 = "rn \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}