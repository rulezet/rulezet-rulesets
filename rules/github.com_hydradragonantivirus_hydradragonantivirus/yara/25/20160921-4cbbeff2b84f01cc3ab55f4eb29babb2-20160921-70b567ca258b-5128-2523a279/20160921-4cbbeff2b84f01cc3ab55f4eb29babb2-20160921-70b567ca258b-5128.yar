rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_70b567ca258b_5128 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "n \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s2 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s3 = "urn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s4 = "return \"AUx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s5 = "turn \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}