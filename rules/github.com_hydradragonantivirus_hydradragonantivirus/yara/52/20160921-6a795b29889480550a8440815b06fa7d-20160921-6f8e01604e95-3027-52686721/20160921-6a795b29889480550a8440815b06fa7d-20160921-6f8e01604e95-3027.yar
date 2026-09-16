rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_6f8e01604e95_3027 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "n fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s2 = "fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DR" ascii
    $s3 = ";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s5 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s6 = "rn \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s7 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}