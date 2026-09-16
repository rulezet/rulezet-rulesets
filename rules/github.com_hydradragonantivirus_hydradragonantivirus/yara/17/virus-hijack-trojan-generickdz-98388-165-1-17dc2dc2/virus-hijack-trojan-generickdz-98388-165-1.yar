rule Virus_Hijack_Trojan_GenericKDZ_98388_165_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_165_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5c482e1794e97ebb9cba0b38c3886ebe2e2d0f9909fe81c7bfc235427a6301e"

  strings:
    $s1 = "IdLY k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}