rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSQPfVg_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSQPfVg_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9992afea7ffd97c8d8d5a7e782f2881e924f55a224cd0dc3360a0db9719a986"

  strings:
    $s1 = "DEAf]A`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}