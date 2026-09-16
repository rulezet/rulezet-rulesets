rule Virus_Hijack_Trojan_GenericKDZ_98388_130_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4868c20e1e3bc44f91ceaf8ce1c42b5148088d7eaddeb752e702020efc06db1a"

  strings:
    $s1 = "wHEt[l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}