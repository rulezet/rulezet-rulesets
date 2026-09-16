rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d79cb1401242328fafa7888a924a109a6cff544316c000dbdde011d9f843f8aa"

  strings:
    $s1 = "%posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}