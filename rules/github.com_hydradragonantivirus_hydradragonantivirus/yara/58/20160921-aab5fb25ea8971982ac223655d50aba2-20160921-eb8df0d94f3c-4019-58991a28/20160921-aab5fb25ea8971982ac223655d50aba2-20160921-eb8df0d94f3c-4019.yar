rule _20160921_aab5fb25ea8971982ac223655d50aba2_20160921_eb8df0d94f3c_4019 {
  meta:
    description = "datamaliciousorder - from files 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s3 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(func" ascii
    $s5 = " fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"P" ascii
    $s6 = "rn \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}