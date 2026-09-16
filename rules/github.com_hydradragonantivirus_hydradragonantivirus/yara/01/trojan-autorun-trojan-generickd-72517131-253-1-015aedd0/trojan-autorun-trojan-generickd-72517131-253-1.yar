rule Trojan_Autorun_Trojan_GenericKD_72517131_253_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_253_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dd8fda5415b6f8674a0b5fbc534cc2d4ed56ecfae93ee10f3677f6db4cd87bb"

  strings:
    $s1 = "CUser, Marketing User, Manufacturing User, Purcha" fullword ascii
    $s2 = "jilT)i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}