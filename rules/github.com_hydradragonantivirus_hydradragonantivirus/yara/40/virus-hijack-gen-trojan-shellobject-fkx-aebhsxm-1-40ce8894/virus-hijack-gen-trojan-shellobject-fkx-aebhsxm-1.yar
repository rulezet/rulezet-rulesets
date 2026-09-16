rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ccac51a8b6731e4fd3c79188384de62ed70d8b6838af6c90b8b96936dde2a2b"

  strings:
    $s1 = "dIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}