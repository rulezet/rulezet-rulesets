rule Trojan_Danger_Trojan_GenericKD_72304918_36_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2469e323b6e4fd204715ba6280e7b10cef42983943e2868b03f3e236b0c941a9"

  strings:
    $s1 = "1Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}