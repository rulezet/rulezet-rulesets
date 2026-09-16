rule Trojan_Danger_Trojan_GenericKD_67166905_121_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b531e2dc36b319542187d949deb37ac65a0049a4a9b6482878a82b8463f82eab"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}