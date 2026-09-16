rule Virus_Hijack_Trojan_GenericKDZ_79663_102_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "376cfbef9171ebfb2f782ace892ea7cf44e2007503fdd21e887f55998a623377"

  strings:
    $s1 = "miSS]u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}