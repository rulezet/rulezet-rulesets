rule Virus_Hijack_Trojan_GenericKDZ_74550_269_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_269_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce09588c6bf5eb2711f137222e8c4cf76a700e93258ab734700cfc920742a65"

  strings:
    $s1 = "z?MIRo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}