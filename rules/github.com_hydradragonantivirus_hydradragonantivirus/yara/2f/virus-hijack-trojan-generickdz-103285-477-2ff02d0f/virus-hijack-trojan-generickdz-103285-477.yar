rule Virus_Hijack_Trojan_GenericKDZ_103285_477 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_477.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a03d3a2dd403e0ea5c260202c9a957cd7fb9fb1f8077c1fbb70303f97ca557a"

  strings:
    $s1 = "5dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}