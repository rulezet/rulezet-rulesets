rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4265 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"

  strings:
    $s1 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii
    $s2 = "on fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s3 = "uck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu" ascii
    $s4 = "),(function fuck(){return \"PDf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck()" ascii
    $s5 = "Dy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}