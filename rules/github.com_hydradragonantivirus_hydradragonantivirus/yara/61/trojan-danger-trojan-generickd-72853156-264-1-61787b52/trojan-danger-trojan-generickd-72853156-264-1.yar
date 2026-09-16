rule Trojan_Danger_Trojan_GenericKD_72853156_264_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_264_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b36987b0ac5c2d04f8ec955a8b9d6e5f7a77517ce06c01be75c6c1c3e45f0a8"

  strings:
    $s1 = "Alias attribute is invalid in the profile schema." fullword wide
    $s2 = "Alias attribute value is not unique in the profile." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}