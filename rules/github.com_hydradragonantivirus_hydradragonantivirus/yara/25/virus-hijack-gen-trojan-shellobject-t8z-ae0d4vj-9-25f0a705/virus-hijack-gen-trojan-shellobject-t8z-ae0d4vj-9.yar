rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeb4eb881719aec30bc9c225b98ecf7ed35fd7f76575cefb27ccb9bc588ae385"

  strings:
    $s1 = "(a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}