rule Virus_Hijack_Trojan_GenericKDZ_105924_80_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_80_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4bb1287afd5c258bae28a3a057597957dbcf30c1e4bcb6ec1f4f739225004a8"

  strings:
    $s1 = "yirr,T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}