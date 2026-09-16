rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "314c05837981da6664565c7904251f77530bb346606e78b93c30001cef4353cc"

  strings:
    $s1 = ":OXBOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}