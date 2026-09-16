rule Trojan_Danger_Trojan_GenericKD_72677122_67 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35f19688ea75c4f9f669b00336d71a581154761f0b33160651a6bdb8537c655d"

  strings:
    $s1 = "System Information.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}