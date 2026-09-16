rule Virus_Hijack_Trojan_GenericKDZ_74550_260_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_260_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e39108be055d7037eb6742f1c2afc0dbb87a77873d07510b59f11cc21d1cfd3f"

  strings:
    $s1 = "w!NetOP" fullword ascii
    $s2 = "t>X{TEaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}