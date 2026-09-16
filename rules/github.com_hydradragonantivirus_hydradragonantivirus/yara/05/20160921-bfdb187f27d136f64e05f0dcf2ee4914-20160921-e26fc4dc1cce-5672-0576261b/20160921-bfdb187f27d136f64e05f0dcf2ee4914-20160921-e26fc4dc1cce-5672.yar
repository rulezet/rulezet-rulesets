rule _20160921_bfdb187f27d136f64e05f0dcf2ee4914_20160921_e26fc4dc1cce_5672 {
  meta:
    description = "datamaliciousorder - from files 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash2       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2 = "){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s3 = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s4 = "){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})" ascii
    $s5 = "\"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}