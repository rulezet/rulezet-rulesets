rule Virus_Hijack_Trojan_GenericKDZ_98388_110_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_110_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01efb44696aab6ebf9892b4ad698dd075c494b17567fd368f87bb470ab26ae51"

  strings:
    $s1 = "tAlA}R)bl S" fullword ascii
    $s2 = "kofT?R" fullword ascii
    $s3 = "h$anuS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}