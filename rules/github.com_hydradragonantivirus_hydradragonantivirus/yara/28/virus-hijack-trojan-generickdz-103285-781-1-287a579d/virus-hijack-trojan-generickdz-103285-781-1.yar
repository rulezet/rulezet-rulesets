rule Virus_Hijack_Trojan_GenericKDZ_103285_781_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_781_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c773834797881fa2c7ea9f758323b8d2bc6908088a127383e2a4b9c5a8fe332"

  strings:
    $s1 = "ewing Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}