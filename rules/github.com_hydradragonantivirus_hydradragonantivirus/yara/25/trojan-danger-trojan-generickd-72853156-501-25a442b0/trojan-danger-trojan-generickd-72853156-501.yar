rule Trojan_Danger_Trojan_GenericKD_72853156_501 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_501.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2beeb0d4188eee89ed3c92dab4a66a7b544b8200b5f79a8f5e28a51a3238d28d"

  strings:
    $s1 = "Microsoft Office Publisher 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}