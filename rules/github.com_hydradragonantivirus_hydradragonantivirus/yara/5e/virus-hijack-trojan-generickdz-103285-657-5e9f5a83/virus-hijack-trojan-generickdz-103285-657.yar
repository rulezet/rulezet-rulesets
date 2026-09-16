rule Virus_Hijack_Trojan_GenericKDZ_103285_657 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_657.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cd9886b84ecc36eeaea5c9e3521bca42e1dd0371e0dc35fba5eec21d10c7b0f"

  strings:
    $s1 = " PlAIt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}