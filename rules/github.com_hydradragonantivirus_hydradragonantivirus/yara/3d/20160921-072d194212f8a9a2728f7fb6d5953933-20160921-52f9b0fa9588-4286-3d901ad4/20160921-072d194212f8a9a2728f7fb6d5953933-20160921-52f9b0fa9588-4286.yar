rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4286 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash4       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash5       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash6       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash7       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash8       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash9       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s2 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck" ascii
    $s3 = "ck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "urn \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s5 = "return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}