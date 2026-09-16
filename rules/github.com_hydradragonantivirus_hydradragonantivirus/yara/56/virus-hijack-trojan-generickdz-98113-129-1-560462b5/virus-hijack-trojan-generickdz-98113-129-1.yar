rule Virus_Hijack_Trojan_GenericKDZ_98113_129_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_129_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f154e486447c6b1848d352a78c7e19eaee7c866f0a6cfaffb216fb62b3998125"

  strings:
    $s1 = "V:qUaB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}