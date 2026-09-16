rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d9a39af92848297649ee8b7e4714c15c75d80415df2289811f1346a100fc068"

  strings:
    $s1 = "g.4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "P#hagi>d}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}