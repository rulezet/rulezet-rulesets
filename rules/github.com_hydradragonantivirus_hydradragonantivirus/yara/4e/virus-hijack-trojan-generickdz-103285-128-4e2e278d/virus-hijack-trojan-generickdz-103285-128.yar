rule Virus_Hijack_Trojan_GenericKDZ_103285_128 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_128.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfd99c6aaabb090499ee715e2cab366570a75243025ef2e208237ec86a5bb390"

  strings:
    $s1 = "mUsk;-Tk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}