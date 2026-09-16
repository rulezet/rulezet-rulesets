rule Virus_Danger_Trojan_GenericKDZ_103285_51 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d4823ecc5bac4f730e9a6b0c367b32ddc920e56457d0c97d3b726c0b16d0c65"

  strings:
    $s1 = "wIDU@Jy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}