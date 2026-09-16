rule Virus_Hijack_Trojan_GenericKDZ_74550_362 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_362.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afebff5935301ff0a6530336a506cb433f4ec21a572d1d4b3fa46f3c34a008e7"

  strings:
    $s1 = "sANk*jn&Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}