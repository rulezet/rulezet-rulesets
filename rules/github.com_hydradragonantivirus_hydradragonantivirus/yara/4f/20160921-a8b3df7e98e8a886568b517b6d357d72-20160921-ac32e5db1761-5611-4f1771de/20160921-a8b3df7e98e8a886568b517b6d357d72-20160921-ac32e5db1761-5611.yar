rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_5611 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_b9eadd20f28216849138290cb6dac4de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"

  strings:
    $s1 = "urn \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s2 = ")(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s3 = "k(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "n \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii
    $s5 = "return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}