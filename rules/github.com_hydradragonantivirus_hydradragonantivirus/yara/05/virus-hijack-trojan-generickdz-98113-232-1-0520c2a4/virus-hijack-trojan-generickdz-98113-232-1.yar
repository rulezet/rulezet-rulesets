rule Virus_Hijack_Trojan_GenericKDZ_98113_232_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_232_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85d823011915378f8349b51f43604199e85a1e3605389b2a476436a10eb59d9d"

  strings:
    $s1 = "<d,NarR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}