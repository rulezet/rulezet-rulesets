rule Trojan_Autorun_Trojan_GenericKD_72250432_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72250432_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ce769972c21377f2b7bcd86624b3acb819947bcfc688f149a8df6a46d5788a"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}