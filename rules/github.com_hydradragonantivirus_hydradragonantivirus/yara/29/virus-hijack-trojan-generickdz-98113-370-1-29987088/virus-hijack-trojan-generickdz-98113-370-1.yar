rule Virus_Hijack_Trojan_GenericKDZ_98113_370_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_370_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295a3b6dd2930ef076a0d8253ca01f72821d301a999a4c7e959d2e17612ea380"

  strings:
    $s1 = ".$oXyl<W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}