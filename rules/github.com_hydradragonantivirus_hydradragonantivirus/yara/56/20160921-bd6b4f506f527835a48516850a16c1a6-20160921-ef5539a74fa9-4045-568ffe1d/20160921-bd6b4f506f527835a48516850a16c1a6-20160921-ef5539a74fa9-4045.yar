rule _20160921_bd6b4f506f527835a48516850a16c1a6_20160921_ef5539a74fa9_4045 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})(),(function fuck" ascii
    $s2 = "urn \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MIl\";})(),(f" ascii
    $s4 = "fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s5 = "{return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})" ascii
    $s6 = "tion fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}