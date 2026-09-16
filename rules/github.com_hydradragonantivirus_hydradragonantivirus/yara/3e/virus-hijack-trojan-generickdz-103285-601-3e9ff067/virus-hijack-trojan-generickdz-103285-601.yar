rule Virus_Hijack_Trojan_GenericKDZ_103285_601 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_601.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50d427c94b900c4f4273cdde7e3d070e283c5c0d1c23e913985b4e2bc655ea1"

  strings:
    $s1 = "$]dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}