rule _20160921_8753c13c904d4c1e9e4a848591336ee8_20160921_962ed1e894cd_5483 {
  meta:
    description = "datamaliciousorder - from files 20160921_8753c13c904d4c1e9e4a848591336ee8.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "eturn \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s2 = "eturn \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s3 = "})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fu" ascii
    $s4 = "turn \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})()" ascii
    $s5 = "on fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}