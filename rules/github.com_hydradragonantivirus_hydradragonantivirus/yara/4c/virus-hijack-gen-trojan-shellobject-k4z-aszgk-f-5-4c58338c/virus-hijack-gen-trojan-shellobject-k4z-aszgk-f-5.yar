rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51712077175aedc943d41437babe0945845328c75720057674b69e0c44571016"

  strings:
    $s1 = "oOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}