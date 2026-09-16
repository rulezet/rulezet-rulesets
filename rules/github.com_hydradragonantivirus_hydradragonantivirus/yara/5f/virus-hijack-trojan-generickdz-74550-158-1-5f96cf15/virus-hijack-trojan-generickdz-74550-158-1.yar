rule Virus_Hijack_Trojan_GenericKDZ_74550_158_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_158_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c4782c34ea61f0ce97ae2631d3b35387431175334e0b1e8e8452d85f271f247"

  strings:
    $s1 = "\"scyT<j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}