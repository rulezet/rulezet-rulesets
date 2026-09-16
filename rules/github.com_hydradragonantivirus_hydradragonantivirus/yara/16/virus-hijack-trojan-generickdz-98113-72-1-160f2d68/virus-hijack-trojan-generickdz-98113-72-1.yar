rule Virus_Hijack_Trojan_GenericKDZ_98113_72_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f731a1648d086b0df577b400842ee97d1127143fd94f11ac723c8b67678e1ff"

  strings:
    $s1 = " Boho " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}