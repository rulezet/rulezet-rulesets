rule Trojan_Danger_Trojan_GenericKD_72677122_315_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_315_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da6829c523e4b2424fe244f3d30c7ac8b67a775c00f9eee2bf1c148889dee7cc"

  strings:
    $s1 = "r&lees" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}