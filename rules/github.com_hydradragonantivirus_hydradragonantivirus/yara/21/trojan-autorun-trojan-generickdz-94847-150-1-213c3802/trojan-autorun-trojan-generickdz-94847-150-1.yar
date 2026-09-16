rule Trojan_Autorun_Trojan_GenericKDZ_94847_150_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_150_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b209bbe8343222353f91df848765e5865b6796f9b8a5ef898561d2265ba792e6"

  strings:
    $s1 = "lauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}