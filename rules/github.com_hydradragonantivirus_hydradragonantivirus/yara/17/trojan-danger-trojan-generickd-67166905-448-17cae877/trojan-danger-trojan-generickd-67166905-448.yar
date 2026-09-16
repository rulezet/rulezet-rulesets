rule Trojan_Danger_Trojan_GenericKD_67166905_448 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_448.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d205ceb5ba616db579d33dfd62958baa5f1d75600daf0903b8f1596256d995cc"

  strings:
    $s1 = "Microsoft Office Outlook 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}