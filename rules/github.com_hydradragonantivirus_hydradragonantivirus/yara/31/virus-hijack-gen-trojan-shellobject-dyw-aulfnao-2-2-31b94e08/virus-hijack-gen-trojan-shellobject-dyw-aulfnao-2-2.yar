rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43e17f7de259d143bc76752a2fca61e312e39059f891f618ea062bdfe348c746"

  strings:
    $s1 = "#]CoCK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}