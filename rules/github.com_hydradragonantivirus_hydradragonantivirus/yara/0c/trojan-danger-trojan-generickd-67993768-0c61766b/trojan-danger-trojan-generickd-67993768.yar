rule Trojan_Danger_Trojan_GenericKD_67993768 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67993768.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5725267005f20df0a04e1ca51ecdfdca1314fba9e85c4ae3eb4d81a6f480b896"

  strings:
    $s1 = "Microsoft Office InfoPath 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}