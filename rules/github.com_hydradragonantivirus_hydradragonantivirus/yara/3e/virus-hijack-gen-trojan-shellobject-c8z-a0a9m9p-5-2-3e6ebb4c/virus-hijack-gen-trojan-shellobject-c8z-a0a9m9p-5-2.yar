rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221567d0ff780331d0fc104c1c1ff41b8ae576ada1a7c1414601c8b8ce973e21"

  strings:
    $s1 = "/{Riem" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}