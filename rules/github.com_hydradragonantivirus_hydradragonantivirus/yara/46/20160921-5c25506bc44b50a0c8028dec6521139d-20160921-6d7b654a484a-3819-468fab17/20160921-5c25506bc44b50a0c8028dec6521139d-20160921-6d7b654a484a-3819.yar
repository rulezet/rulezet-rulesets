rule _20160921_5c25506bc44b50a0c8028dec6521139d_20160921_6d7b654a484a_3819 {
  meta:
    description = "datamaliciousorder - from files 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash2       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s2 = " \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\"" ascii
    $s4 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fu" ascii
    $s5 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return " ascii
    $s6 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}