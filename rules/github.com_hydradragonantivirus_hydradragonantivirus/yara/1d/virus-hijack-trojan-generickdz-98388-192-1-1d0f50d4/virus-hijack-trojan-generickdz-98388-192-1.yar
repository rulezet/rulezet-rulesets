rule Virus_Hijack_Trojan_GenericKDZ_98388_192_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_192_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab951c23b4bf0ddd74c621513ad67dc005aa0c3631f77c06ea760f9fd90681c"

  strings:
    $s1 = "SHun{W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}