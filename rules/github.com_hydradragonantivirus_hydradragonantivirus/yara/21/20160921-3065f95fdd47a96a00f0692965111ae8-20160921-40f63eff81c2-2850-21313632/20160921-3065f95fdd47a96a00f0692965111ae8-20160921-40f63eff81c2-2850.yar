rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_40f63eff81c2_2850 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash3       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s2 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Zy\";})(),(function fuck(" ascii
    $s3 = "(function fuck(){return \"Av\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"CCb\";})()" ascii
    $s5 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(functio" ascii
    $s6 = "urn \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s7 = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}