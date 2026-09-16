rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfb343d3e1336a95c12066e1c1840e628cbc33dc6dd9d54dc81f77fd379dfd96"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.co{/xap/1.0/sType/ResourceEvent#" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}