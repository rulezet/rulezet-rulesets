rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_55_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e227a8ccdeae8816c152f9ac7cb22c9439194892d2adb12d6ec7d3575bcd0b91"

  strings:
    $s1 = "oakyM,k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}