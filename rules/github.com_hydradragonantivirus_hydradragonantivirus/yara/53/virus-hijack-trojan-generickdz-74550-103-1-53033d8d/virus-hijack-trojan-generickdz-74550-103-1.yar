rule Virus_Hijack_Trojan_GenericKDZ_74550_103_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_103_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61a63d2be1d9974a096f6da3a6a6bdfb9bd40766fc91afcb54453b449130e06"

  strings:
    $s1 = ",W#\"EN>Kral>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}