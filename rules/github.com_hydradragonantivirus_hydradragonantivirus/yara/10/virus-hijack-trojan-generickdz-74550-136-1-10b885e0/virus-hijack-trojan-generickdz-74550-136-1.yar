rule Virus_Hijack_Trojan_GenericKDZ_74550_136_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7de1c768b83bf601ef4d6dd8cb9172e10baca99701ff05fe9954ada6a15fb106"

  strings:
    $s1 = "PElt!6" fullword ascii
    $s2 = "locK(}m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}