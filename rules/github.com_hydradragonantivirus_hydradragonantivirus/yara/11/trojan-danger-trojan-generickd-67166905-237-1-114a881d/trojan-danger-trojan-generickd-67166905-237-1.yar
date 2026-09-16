rule Trojan_Danger_Trojan_GenericKD_67166905_237_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_237_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94f0323c4d9e84f26f1dfdbe7316fa7d2b4bdac60d927b0cbaa669e15ede1068"

  strings:
    $s1 = "\"available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}