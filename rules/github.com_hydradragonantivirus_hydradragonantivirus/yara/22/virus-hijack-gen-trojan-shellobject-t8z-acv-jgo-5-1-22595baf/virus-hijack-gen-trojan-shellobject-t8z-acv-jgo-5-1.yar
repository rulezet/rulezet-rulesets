rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18b9925ddc9f3e04ac516751fa8976b1fced8bcb68a0dcc1b9f4762dc092451b"

  strings:
    $s1 = "om/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEven" ascii
    $s2 = "xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateD" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}