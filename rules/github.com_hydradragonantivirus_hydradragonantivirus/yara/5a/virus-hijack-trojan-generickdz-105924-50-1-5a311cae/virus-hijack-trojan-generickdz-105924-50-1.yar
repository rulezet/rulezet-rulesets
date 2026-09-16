rule Virus_Hijack_Trojan_GenericKDZ_105924_50_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66113250e0ec4ecb3bd0fc452fb1f0e060ce4290a04703e3e72e2d72430ff1d9"

  strings:
    $s1 = "7K>teAd'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}