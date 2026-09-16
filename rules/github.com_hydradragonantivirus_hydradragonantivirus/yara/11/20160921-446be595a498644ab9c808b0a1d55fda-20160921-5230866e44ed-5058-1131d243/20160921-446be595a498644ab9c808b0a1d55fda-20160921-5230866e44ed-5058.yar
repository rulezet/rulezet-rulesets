rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_5230866e44ed_5058 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_7463e4586b309c15d7048a37c63c1226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash3       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"

  strings:
    $s1 = "turn \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2 = "LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s3 = " fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s4 = "unction fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5 = "return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}