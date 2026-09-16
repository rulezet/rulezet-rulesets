rule _20160921_b6d1e9aee3a026c6f266b107f0b88f18_20160921_c42fb5c75aea_5650 {
  meta:
    description = "datamaliciousorder - from files 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s2 = ",(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s3 = "\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s4 = "eturn \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s5 = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}