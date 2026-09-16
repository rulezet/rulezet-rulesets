rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_3a2902eaca0b_4104 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash3       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash4       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1 = "rn \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s2 = "urn \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s3 = "urn \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s4 = " fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s5 = "(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}