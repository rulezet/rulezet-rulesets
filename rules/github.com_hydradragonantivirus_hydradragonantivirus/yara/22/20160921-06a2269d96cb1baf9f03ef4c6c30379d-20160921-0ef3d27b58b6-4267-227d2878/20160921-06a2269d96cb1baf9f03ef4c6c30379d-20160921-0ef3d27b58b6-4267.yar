rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4267 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2 = "{return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3 = "fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s4 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}