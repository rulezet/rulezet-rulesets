rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_5e9244484429_5141 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_5e9244484429cd897ec88fe97140c29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"

  strings:
    $s1 = "ction fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s2 = "(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";" ascii
    $s3 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s4 = " fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs" ascii
    $s5 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}