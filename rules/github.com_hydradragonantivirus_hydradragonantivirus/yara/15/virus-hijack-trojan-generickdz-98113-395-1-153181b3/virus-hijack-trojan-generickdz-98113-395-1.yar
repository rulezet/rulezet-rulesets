rule Virus_Hijack_Trojan_GenericKDZ_98113_395_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_395_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0463bdc44a8d7f20ff4d72a98dfb4cf672fe2279d4d002303ab325795649d70"

  strings:
    $s1 = "i:$POOr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}