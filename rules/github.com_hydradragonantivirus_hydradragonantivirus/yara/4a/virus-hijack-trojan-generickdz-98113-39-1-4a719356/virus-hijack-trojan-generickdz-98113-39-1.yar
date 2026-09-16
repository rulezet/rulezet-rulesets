rule Virus_Hijack_Trojan_GenericKDZ_98113_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a68ebb591c02937f3375846fd5841a88e6001d1098a1ff10fb0a617c5c41470a"

  strings:
    $s1 = "f.`cRIb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}