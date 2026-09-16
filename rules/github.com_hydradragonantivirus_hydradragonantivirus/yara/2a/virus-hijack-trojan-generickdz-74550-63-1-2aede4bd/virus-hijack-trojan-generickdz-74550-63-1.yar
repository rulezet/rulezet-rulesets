rule Virus_Hijack_Trojan_GenericKDZ_74550_63_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_63_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a692cacb1fa4e6816c42063a478d1a5ce99954571f79686f7e5f94b3ad4e0594"

  strings:
    $s1 = "oq)FlAW" fullword ascii
    $s2 = "vz,sNIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}