rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4266 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"

  strings:
    $s1 = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){re" ascii
    $s2 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})()" ascii
    $s3 = "})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(" ascii
    $s4 = "on fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s5 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}