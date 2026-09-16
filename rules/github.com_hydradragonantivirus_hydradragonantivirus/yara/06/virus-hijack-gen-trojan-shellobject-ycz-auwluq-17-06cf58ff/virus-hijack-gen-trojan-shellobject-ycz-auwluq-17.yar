rule Virus_Hijack_Gen_Trojan_ShellObject_YCZ_auWluQ_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.YCZ@auWluQ_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636ee69113aadd00c6c0f0d544d27cd9b62ba85c7fec139530d9b2b5e4c333d6"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}