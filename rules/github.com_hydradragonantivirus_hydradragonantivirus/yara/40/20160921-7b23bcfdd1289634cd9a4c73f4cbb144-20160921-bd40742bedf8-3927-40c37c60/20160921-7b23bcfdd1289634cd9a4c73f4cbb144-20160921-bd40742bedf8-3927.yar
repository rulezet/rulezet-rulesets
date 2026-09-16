rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_bd40742bedf8_3927 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "){return \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2 = "{return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";}" ascii
    $s3 = "on fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s4 = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s5 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"P" ascii
    $s6 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}