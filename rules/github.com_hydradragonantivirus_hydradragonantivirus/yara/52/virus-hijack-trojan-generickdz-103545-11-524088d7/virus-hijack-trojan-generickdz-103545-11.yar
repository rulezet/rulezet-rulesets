rule Virus_Hijack_Trojan_GenericKDZ_103545_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49e28dc8f6bcbe64ba006fb89d117ac2c86e385320ac237dab8e0f25d166a84a"

  strings:
    $s1 = "9$software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}