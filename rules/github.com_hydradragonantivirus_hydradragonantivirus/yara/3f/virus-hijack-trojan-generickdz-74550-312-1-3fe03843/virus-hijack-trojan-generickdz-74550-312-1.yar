rule Virus_Hijack_Trojan_GenericKDZ_74550_312_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_312_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfd9732e0fca8fc3083c6867882f491593101f2a327ed735713b4012bb346a8f"

  strings:
    $s1 = "j`GALI" fullword ascii
    $s2 = "(prUh>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}