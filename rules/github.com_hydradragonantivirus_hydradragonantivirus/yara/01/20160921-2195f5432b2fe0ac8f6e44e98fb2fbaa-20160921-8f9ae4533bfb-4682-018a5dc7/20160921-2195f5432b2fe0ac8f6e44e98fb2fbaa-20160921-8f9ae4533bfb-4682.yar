rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_8f9ae4533bfb_4682 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash3       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash4       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "nction fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s2 = "ion fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s3 = "return \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(" ascii
    $s4 = "(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){re" ascii
    $s5 = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}