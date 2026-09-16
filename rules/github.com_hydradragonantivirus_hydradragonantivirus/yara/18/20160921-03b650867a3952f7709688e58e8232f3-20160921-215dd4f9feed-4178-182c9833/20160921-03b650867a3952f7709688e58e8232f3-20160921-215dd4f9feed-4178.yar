rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_215dd4f9feed_4178 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash3       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash4       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1 = "nction fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function " ascii
    $s3 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return " ascii
    $s4 = "return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s5 = "ck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}