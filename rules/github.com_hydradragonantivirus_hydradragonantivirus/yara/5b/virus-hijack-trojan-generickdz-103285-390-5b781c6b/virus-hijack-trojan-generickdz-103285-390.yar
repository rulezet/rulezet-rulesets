rule Virus_Hijack_Trojan_GenericKDZ_103285_390 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_390.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd664da6a776235828fa2164cecef43daeb85a09fca5438095ce599fc66ee25d"

  strings:
    $s1 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}