rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6bd8894237764814dcb4ce50dfa7f175f7f6cd10611fbe27ba8b643d2c0fb4"

  strings:
    $s1 = "and software vendors, so that they can use the information to i`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}