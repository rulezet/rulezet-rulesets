rule Virus_Hijack_Trojan_Agent_DQQO_223_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_223_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bca883e36b23aa500a55d41482e4b684f4dcb852d2dfd6e6e07c689a5ab13c0a"

  strings:
    $s1 = "Event#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xm" ascii
    $s2 = "Event#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xm" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}