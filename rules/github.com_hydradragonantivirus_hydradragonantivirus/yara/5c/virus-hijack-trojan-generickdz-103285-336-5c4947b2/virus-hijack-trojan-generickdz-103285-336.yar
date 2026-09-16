rule Virus_Hijack_Trojan_GenericKDZ_103285_336 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_336.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e973996c932139d29fe17ad5a29f5bd6bafffe6e023d5aa0e4f8467b27fcbd7"

  strings:
    $s1 = "kWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}