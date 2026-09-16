rule Virus_Hijack_Trojan_GenericKDZ_105924_524_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_524_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0e503aa0a6183dec50428895b800f6dfb881f3a784a2ce374d674194dbacea0"

  strings:
    $s1 = "jl \"WirE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}