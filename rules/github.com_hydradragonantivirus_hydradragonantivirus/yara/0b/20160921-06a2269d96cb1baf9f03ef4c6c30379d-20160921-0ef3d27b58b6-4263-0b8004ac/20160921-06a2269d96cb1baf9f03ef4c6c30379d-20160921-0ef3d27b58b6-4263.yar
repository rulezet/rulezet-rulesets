rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4263 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_7e2de7c26f136a1a958818752613cac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"

  strings:
    $s1 = ";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fu" ascii
    $s2 = "})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(" ascii
    $s3 = "),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s4 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s5 = "function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}