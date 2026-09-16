rule Virus_Hijack_Trojan_GenericKDZ_74550_47_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a209707d53bbeabc5cd2c5663c0864b9e3aa9784e46cebf38bda0d0201014b34"

  strings:
    $s1 = "pOUF[oZ" fullword ascii
    $s2 = "m\"CoST" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}