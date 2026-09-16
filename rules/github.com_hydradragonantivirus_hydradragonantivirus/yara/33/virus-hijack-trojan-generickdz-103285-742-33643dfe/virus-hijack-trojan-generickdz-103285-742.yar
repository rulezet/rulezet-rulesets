rule Virus_Hijack_Trojan_GenericKDZ_103285_742 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_742.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae4247124c4d48007b309a89fe6aa665176ee02ce69d2674afaed2d9225c94af"

  strings:
    $s1 = "$6University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}