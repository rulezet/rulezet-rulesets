rule Virus_Hijack_Gen_Trojan_ShellObject_u8Y_aivto4c_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Y@aivto4c_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fffda66797e460015fcfbd667ab45412dc7af920528642bf935a72095f498ae7"

  strings:
    $s1 = "pe/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}