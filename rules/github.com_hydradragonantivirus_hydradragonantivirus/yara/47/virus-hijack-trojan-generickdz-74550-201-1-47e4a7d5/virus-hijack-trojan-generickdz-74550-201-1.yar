rule Virus_Hijack_Trojan_GenericKDZ_74550_201_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_201_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9501f3315b7a71b0fcb35c1dcc84324a632b1774a684c4641664ea8f435cbee"

  strings:
    $s1 = "T!OgRE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}