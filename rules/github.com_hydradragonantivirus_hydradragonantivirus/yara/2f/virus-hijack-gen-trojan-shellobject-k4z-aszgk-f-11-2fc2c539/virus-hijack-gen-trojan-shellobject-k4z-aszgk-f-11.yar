rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26a93d456fa8d043ac0c8aaa2762a809c42608104d5bf21112f2ac36c7247188"

  strings:
    $s1 = "LOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}