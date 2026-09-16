rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a95ac74bdd1396b89dea1c8561214c0e866e9d52eaf7d1a18f31c87b80201299"

  strings:
    $s1 = "E[Workshop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}