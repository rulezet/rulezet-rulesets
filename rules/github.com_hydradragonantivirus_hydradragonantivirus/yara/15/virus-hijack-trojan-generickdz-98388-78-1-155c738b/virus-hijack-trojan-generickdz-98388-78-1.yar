rule Virus_Hijack_Trojan_GenericKDZ_98388_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06163add7c6c2c02311e6cb1b2c84d9b1cb36e792b882347c839b3185068c137"

  strings:
    $s1 = "AMeN,*49" fullword ascii
    $s2 = "zf)pavY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}