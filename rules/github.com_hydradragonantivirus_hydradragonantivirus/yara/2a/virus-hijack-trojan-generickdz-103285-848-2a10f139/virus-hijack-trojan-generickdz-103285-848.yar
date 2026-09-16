rule Virus_Hijack_Trojan_GenericKDZ_103285_848 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_848.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d8996a1b553878097944668d6bde070b33940e9b513a018b7f94a96008ad02f"

  strings:
    $s1 = "agreements or representations, written or oral, regarding such programs and/or service`" fullword ascii
    $s2 = "Sremainder of Section B remaining in full force and effect." fullword ascii
    $s3 = "HeNsH}N[HUNCH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}