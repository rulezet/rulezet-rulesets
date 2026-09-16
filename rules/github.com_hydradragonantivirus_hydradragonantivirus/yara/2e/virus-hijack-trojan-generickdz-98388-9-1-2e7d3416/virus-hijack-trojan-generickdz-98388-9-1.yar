rule Virus_Hijack_Trojan_GenericKDZ_98388_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae13517ae874b82c367a08e6300415a839b48673b2cddab54540aeee14e0ee9f"

  strings:
    $s1 = "MENy?2" fullword ascii
    $s2 = "ny#t<kaId" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}