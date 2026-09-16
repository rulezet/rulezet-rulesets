rule Trojan_Danger_Trojan_GenericKD_67269844_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0576670c2bcf4096c27f914180aea2fb21404c657678f8e36d49be84ab237055"

  strings:
    $s1 = "x'must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}