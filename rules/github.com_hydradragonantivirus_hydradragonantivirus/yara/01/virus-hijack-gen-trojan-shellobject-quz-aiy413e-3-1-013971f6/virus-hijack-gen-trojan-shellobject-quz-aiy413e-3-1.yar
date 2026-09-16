rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1db034306cac29923c02edacad42119e6021d532c1f285238d714c64e02d9fcb"

  strings:
    $s1 = "]flEa>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}