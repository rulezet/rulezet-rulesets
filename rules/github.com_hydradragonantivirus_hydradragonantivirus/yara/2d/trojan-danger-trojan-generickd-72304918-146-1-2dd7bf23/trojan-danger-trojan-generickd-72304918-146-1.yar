rule Trojan_Danger_Trojan_GenericKD_72304918_146_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_146_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24fccdd03ea89ab9dd3ca9e5ab0f4ff21b7078720c7fc7797291f51708af4651"

  strings:
    $s1 = "kIavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}