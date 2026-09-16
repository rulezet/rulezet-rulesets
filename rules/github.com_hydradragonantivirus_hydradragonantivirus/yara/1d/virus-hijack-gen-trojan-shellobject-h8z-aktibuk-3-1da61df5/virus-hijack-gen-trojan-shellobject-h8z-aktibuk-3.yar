rule Virus_Hijack_Gen_Trojan_ShellObject_h8Z_aKTibuk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Z@aKTibuk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a7537ead6eeb4fcc3e660d05414cefecd853690cc7749dd80880ce19b4a1f2a"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}