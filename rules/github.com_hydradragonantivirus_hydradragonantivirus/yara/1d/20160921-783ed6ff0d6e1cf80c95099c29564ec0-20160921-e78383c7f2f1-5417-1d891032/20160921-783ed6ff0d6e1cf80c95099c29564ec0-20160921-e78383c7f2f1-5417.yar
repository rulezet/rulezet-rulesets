rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_e78383c7f2f1_5417 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "{return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s2 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s3 = "n \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s4 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UO" ascii
    $s5 = " \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}