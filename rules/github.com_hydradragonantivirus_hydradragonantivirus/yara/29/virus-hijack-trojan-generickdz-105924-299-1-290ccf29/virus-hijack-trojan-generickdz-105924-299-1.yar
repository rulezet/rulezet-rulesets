rule Virus_Hijack_Trojan_GenericKDZ_105924_299_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e92a283b9965e46b07560d0a568d4db99c42f2269b433bd81e5476dd4c64f4"

  strings:
    $s1 = "SOoT%8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}