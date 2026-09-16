rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_1e07803d7c44_4107 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash3       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash4       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash5       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck()" ascii
    $s2 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s3 = "rn \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s5 = "n fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}