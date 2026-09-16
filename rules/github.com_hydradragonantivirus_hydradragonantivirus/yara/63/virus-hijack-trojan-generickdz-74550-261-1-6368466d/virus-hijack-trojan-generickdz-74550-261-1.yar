rule Virus_Hijack_Trojan_GenericKDZ_74550_261_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_261_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50f718baa309900a01bf6b0154be96910f8839aa85cac844f38cabacfd986180"

  strings:
    $s1 = "SEal]n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}