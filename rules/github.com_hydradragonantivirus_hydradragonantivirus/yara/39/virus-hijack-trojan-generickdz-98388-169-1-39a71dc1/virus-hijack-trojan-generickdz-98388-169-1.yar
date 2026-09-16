rule Virus_Hijack_Trojan_GenericKDZ_98388_169_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_169_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23e0a9d14e4c65eed9b2a9930a53352258c7cafe2aff3e4e1881515ca00c6223"

  strings:
    $s1 = "+)CoXa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}