rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_446be595a498_4675 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash3       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash4       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash5       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s2 = "eturn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s3 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s4 = "rn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s5 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}