rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea6b4827e11ad0490b542b480300914572798b84f85498d2b1676a49c287c4a0"

  strings:
    $s1 = "LOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}