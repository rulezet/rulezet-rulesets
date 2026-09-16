rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a9510082e17ecb5c5400c3fcead8b9ebf8fde5497ebacb5950fa0a58003d11f"

  strings:
    $s1 = "|a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}