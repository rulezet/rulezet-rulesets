rule Virus_Hijack_Trojan_GenericKDZ_98113_217_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e397ff22f9a3b75478b9c218282310095282086acbdc376589b64229975475f"

  strings:
    $s1 = "E{WYnN;wS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}