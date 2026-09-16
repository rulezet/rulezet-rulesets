rule Virus_Hijack_Trojan_GenericKDZ_74550_280_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a64fb840f277950d4f3e215b29fcf34293d13efa674b41396abbc8762c658d6f"

  strings:
    $s1 = "PedA}IZ0" fullword ascii
    $s2 = "POBS[w" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}