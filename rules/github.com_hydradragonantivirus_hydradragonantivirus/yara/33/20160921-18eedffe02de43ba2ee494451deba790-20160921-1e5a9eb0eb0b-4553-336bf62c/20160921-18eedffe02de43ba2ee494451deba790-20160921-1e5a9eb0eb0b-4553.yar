rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_4553 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash4       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash5       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash6       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"

  strings:
    $s1 = "turn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s2 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s3 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s4 = "e\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function " ascii
    $s5 = "k(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}