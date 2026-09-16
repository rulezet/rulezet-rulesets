rule Virus_Hijack_Trojan_EmotetU_Gen_nW0_h8lzSHmi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.nW0@h8lzSHmi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6119f3f0dfd07dd69035cd2be5b3664fb4203c0c4e240ba34a10c2cf8864d33"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windo$s)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windo$s)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}