rule Virus_Hijack_Trojan_GenericKDZ_99416_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744bd328f34ef8546e920971fffdc4cb310ab9ce7f02d193893c457f0329bb47"

  strings:
    $s1 = ")User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}