rule Virus_Hijack_Trojan_GenericKDZ_74550_303_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_303_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b0bff5c24c4b4d1e0b7c5ef6387a21c68505104828415a493aa3332fbe926f2"

  strings:
    $s1 = "Eddy&5UY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}