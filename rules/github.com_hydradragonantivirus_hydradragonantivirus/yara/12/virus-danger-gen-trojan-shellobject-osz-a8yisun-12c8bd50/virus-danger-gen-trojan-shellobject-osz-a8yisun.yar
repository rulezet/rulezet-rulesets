rule Virus_Danger_Gen_Trojan_ShellObject_oSZ_a8YIsUn {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.oSZ@a8YIsUn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bca82d321e9282d230b11c0532b5b239a662e4cbf1feeeb3bf101ef0728389d"

  strings:
    $s1 = "}remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}