rule Virus_Hijack_Trojan_GenericKDZ_98113_198 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_198.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c053edcf8729a05b16357b02c7240a13d4946ca9ac076180b74e9b62473d7c30"

  strings:
    $s1 = "\\hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}