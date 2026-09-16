rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00f3958f96efac084edd5b5ec208cbed87e4dbcd5da06279c9dd691ffc7158bc"

  strings:
    $s1 = ",gfunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}