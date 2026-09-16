rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_5c9dd9a0e8a8_4342 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash3       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "uck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"YQt\"" ascii
    $s2 = "\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s3 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function " ascii
    $s5 = "fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}