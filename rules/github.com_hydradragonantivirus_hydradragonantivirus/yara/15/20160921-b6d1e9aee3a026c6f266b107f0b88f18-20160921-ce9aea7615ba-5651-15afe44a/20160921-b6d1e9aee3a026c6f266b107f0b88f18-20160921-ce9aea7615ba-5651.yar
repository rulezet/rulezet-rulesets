rule _20160921_b6d1e9aee3a026c6f266b107f0b88f18_20160921_ce9aea7615ba_5651 {
  meta:
    description = "datamaliciousorder - from files 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"AJs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s2 = "fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii
    $s3 = "{return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})" ascii
    $s4 = "fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"I" ascii
    $s5 = "n \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}