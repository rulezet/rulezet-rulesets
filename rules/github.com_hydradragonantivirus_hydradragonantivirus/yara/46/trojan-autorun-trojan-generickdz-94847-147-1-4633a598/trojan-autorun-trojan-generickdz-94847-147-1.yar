rule Trojan_Autorun_Trojan_GenericKDZ_94847_147_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c87603b2319cc85913f12cc78852015039b9f7f6fa0294fe8f3533422822892"

  strings:
    $s1 = "Eauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}