rule Virus_Hijack_Trojan_GenericKDZ_79663_90_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9d80f19c65c961d3f34e9919a54b5917300c237c8e863b8acfe58bc9f3f73ca"

  strings:
    $s1 = "buRN?C0[]O<+G" fullword ascii
    $s2 = "`|Q%KLoM" fullword ascii
    $s3 = "j]puSs`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}