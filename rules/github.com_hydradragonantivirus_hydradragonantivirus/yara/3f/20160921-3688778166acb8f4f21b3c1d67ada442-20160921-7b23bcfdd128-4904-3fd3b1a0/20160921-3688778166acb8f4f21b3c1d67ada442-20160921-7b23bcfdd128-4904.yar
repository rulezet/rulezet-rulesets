rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_7b23bcfdd128_4904 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash3       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(" ascii
    $s2 = "ion fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s3 = "turn \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s4 = "),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s5 = "\"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}