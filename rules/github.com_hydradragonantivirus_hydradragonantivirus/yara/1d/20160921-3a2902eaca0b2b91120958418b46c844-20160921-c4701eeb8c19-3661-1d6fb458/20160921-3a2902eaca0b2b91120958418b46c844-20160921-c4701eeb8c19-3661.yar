rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_c4701eeb8c19_3661 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"

  strings:
    $s1 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s2 = "unction fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s3 = "nction fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s5 = "y\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(function" ascii
    $s6 = "f\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}