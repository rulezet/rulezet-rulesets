rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_5612 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash4       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "Ai\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s2 = "eturn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s3 = "urn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s4 = "eturn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})()" ascii
    $s5 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}