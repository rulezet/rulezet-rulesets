rule Virus_Hijack_Trojan_GenericKDZ_98388_100_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_100_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c365eb541213069948519b604426893e37258a80a64d1ab4fafb773b0fd781e"

  strings:
    $s1 = "HiNG$lY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}