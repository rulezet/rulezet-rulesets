rule Virus_Hijack_Trojan_GenericKDZ_74550_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b13b3433dfe246103013bf561b06444734ebbe4633c6f2ce58926d223e0a829"

  strings:
    $s1 = "R#siGH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}