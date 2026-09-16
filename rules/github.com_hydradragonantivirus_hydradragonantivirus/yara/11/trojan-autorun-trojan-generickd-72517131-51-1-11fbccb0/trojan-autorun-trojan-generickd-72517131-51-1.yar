rule Trojan_Autorun_Trojan_GenericKD_72517131_51_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cf02415ce4dd814177eec5a19daf334ca65d2326c9f88d4cbd3c383c1551bf7"

  strings:
    $s1 = "this notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}