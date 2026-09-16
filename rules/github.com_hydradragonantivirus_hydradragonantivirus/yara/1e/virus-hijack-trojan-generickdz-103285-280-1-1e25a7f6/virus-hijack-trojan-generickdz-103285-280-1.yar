rule Virus_Hijack_Trojan_GenericKDZ_103285_280_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31845caf7c81c960886391034bafa87a453e7d51f073cd72b04eccd1c37995f0"

  strings:
    $s1 = "ewing Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}