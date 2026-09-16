rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_a160e4a38580_3878 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"

  strings:
    $s1 = "){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"SUi\";})" ascii
    $s2 = "urn \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(f" ascii
    $s3 = " fuck(){return \"DHd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s4 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return" ascii
    $s5 = "(function fuck(){return \"To\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s6 = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}