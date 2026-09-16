rule Virus_Hijack_Trojan_GenericKDZ_103285_809 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_809.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41820e98bdcc329679e1178b48e233f45e2adb499289115586d8b20c5534db81"

  strings:
    $s1 = "-dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}