rule Virus_Hijack_Trojan_GenericKDZ_99416_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1afc2a5a99003eba64dad91bea3290ff06583f9b686149e884eaaa9d8ed967"

  strings:
    $s1 = "Ol\"kUDU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}