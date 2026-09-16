rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_5c9dd9a0e8a8_4339 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash3       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "eturn \"CTm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})()" ascii
    $s2 = "\"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3 = "Ux\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s4 = "rn \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})(),(fun" ascii
    $s5 = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}