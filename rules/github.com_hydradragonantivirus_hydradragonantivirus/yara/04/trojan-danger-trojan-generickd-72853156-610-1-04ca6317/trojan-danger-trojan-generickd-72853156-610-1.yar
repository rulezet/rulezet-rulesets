rule Trojan_Danger_Trojan_GenericKD_72853156_610_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_610_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce5d0546881c9c801ad17058ed33f0ad78383604b826b6cd2b19c6f1db1286f"

  strings:
    $s1 = "Clock Microsoft " fullword wide
    $s2 = "Clock " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}