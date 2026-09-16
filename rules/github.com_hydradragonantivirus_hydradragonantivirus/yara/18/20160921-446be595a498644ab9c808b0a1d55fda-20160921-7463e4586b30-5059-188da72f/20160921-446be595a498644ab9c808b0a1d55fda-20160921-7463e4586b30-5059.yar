rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_5059 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = " \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s2 = "o\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function " ascii
    $s3 = "n \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s4 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Zy\";})" ascii
    $s5 = "(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}