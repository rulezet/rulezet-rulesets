rule Virus_Hijack_Trojan_GenericKDZ_74550_218_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35ff82a2a5bd2a9f0915685213a18a2e6e284ecdea285c6e85298c1954a6ace3"

  strings:
    $s1 = "@NeTh%=kr" fullword ascii
    $s2 = "ShAp]0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}