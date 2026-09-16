rule Trojan_Danger_Trojan_GenericKD_72853156_430 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_430.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "699ccd6f4a649a04a5ebb9109a584f250725446fa5068dcc4f23d9bd91d6153e"

  strings:
    $s1 = "Microsoft Office OneNote 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}