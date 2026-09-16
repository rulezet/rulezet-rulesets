rule Virus_Hijack_Trojan_GenericKDZ_103285_523_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_523_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fec7477589b7af8b351a80944a73e434a8135ec0b431f7c8121c804fd94053c4"

  strings:
    $s1 = ".IEC 61966-2.1 Default" fullword ascii
    $s2 = "RGB colour space " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}