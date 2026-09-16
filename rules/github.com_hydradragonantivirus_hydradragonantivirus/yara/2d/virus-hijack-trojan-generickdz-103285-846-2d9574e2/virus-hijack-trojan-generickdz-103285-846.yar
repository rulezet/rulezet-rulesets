rule Virus_Hijack_Trojan_GenericKDZ_103285_846 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_846.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c23b65c721b3571310c56f37d450e675d790c995742739a3bb45b4ff94ac1dc"

  strings:
    $s1 = "?dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}