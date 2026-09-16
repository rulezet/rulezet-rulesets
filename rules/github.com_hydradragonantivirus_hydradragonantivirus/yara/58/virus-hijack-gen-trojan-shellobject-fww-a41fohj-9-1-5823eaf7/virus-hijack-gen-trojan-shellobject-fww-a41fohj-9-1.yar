rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e49d5a5be4d06f1b6ec646c3b87800b4b4368f16d0392e6f2a0380d0003ab5ef"

  strings:
    $s1 = "<description>Safel</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}