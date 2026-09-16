rule Virus_Hijack_Trojan_GenericKDZ_98388_218_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aef7c2d69156cbc0c01d4835dcf234ce350017ed02a6e1e546940e64c35a231f"

  strings:
    $s1 = "sNOd?}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}