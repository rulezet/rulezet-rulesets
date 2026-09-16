rule Virus_Hijack_Trojan_GenericKDZ_103285_67 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "670a96e58438d90e4b8564e103b5dd040feace9b73f74a5c413624df5023fc96"

  strings:
    $s1 = "{University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}