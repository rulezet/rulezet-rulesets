rule Virus_Hijack_Trojan_GenericKDZ_98113_384_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_384_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c3dff9d8865d8aa95e58b9c781d3c202edefaebbfcfdfa3cd5b646d2c381e3a"

  strings:
    $s1 = "Posy(!g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}