rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6678ad0dbd2e1d0b0d35d49f9624503d15652ab8a28f312978ead156fa58191"

  strings:
    $s1 = "-remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}