rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e73d345d0f5148a11431e99b3537e5b2a7735bff72a85337c609e0fb4658e52"

  strings:
    $s1 = "Ofunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}