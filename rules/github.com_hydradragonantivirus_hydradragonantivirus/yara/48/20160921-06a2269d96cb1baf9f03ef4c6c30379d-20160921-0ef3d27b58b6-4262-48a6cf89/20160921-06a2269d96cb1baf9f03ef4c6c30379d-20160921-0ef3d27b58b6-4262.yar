rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4262 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash4       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1 = "i\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s3 = "k(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn" ascii
    $s4 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s5 = "ion fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}