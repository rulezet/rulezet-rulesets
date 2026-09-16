rule Trojan_Danger_Trojan_GenericKD_72853156_502 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_502.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d8e6df603d125e2cf18238ceaa6096065cb9cb98a61d1c82e0da1c4c369ae9"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}