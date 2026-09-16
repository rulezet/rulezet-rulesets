rule _20160921_abc9044816c2455dc24ac338746b6bd5_20160921_bd40742bedf8_5625 {
  meta:
    description = "datamaliciousorder - from files 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s2 = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck" ascii
    $s3 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s4 = "uck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs" ascii
    $s5 = "turn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}