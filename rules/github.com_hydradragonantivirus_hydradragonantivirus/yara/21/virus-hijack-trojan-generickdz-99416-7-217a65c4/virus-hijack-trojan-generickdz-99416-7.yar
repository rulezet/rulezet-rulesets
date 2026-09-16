rule Virus_Hijack_Trojan_GenericKDZ_99416_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e5d35c6b21ab8a35bd4ba145deb55b154b2966d741abdfad4201afd69ac670"

  strings:
    $s1 = "\\User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}