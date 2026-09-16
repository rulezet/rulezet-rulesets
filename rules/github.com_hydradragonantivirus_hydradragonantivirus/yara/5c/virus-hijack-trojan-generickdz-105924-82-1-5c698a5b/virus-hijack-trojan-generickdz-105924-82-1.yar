rule Virus_Hijack_Trojan_GenericKDZ_105924_82_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_82_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5795e208531e8cf5ce1c0d8df220e64d553de2e680c4b1aaf73f4f267f59f008"

  strings:
    $s1 = "eRuc>h@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}