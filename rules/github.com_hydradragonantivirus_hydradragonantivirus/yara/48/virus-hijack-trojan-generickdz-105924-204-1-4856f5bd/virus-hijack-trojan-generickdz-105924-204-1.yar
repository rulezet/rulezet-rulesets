rule Virus_Hijack_Trojan_GenericKDZ_105924_204_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12deef025402c21319e0478ff6fe9527f0cc6f4e76e631a67c07acd14f773387"

  strings:
    $s1 = "Microsoft (R) .NET Framework IL Assembler.  Version 2.0.50727.5420" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}