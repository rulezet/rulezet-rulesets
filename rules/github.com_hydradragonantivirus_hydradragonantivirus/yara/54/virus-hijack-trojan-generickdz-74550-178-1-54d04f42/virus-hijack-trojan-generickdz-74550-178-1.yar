rule Virus_Hijack_Trojan_GenericKDZ_74550_178_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5a860d4e9a42f6d7f12dde223bddfa8b5850fee4b3c4478036a28a7ca5ac59f"

  strings:
    $s1 = "lEUd{L}" fullword ascii
    $s2 = "tAra}mB" fullword ascii
    $s3 = "G$Knob#" fullword ascii
    $s4 = "?DiAn[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}