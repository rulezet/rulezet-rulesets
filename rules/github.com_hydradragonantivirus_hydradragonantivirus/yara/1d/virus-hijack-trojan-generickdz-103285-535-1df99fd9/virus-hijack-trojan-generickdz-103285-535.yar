rule Virus_Hijack_Trojan_GenericKDZ_103285_535 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_535.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e7980cff8fd05fcc28031b9a3c98c636e3d38118ca7363c85770b84fc49efdd"

  strings:
    $s1 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}