rule Virus_Hijack_Trojan_GenericKDZ_79663_45_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31fd58655e18b8659f2f713a53e5fe1ab369e737aa360917a5f595ebe1f9715b"

  strings:
    $s1 = "a?mAGi{" fullword ascii
    $s2 = "fUTE}z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}