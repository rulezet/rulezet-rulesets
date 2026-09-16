rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_446be595a498_2335 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash3       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"

  strings:
    $s1 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){" ascii
    $s2 = "),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DWe\";})(),(function fuck()" ascii
    $s3 = "){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(" ascii
    $s4 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s5 = "n \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s6 = "n fuck(){return \"Ik\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"O" ascii
    $s7 = "turn \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8 = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}