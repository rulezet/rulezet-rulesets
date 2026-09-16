rule Virus_Hijack_Trojan_GenericKDZ_98113_296_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_296_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "821634ec30a8152095cdb664520fb8cb8f9fac15c78d4814db3dd7fdd3bd039c"

  strings:
    $s1 = "u#BASH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}