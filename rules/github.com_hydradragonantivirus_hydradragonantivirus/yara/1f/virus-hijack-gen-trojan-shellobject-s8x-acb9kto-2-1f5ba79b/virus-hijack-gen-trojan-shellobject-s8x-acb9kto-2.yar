rule Virus_Hijack_Gen_Trojan_ShellObject_s8X_aCb9kto_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.s8X@aCb9kto_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "359d2b5c913fa7c7e1cbf886e8734be9ad2635d19db2b3d33490ec1c730ca2f8"

  strings:
    $s1 = "om/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEven" ascii
    $s2 = "xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateD" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}