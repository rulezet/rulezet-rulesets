rule Virus_Hijack_Trojan_GenericKDZ_74550_187_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59b95e3f4cff44332467f4a1543e5a8bef3909157ed2d1985e16b973fe2c3106"

  strings:
    $s1 = "puxY)T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}