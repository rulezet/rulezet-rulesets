rule _20160921_91af5c220d1ea27d72d05f472ba8fa16_20160921_bfdb187f27d1_5542 {
  meta:
    description = "datamaliciousorder - from files 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1 = "f\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s2 = "on fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s5 = " \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}