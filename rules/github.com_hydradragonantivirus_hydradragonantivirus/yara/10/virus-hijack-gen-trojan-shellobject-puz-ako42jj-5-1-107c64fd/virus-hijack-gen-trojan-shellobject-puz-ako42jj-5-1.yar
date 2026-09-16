rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f521741ea7aca15e6dc3a3c8973b48e970967d900251df647b90bc67d4f88ad"

  strings:
    $s1 = "<dEnT)" fullword ascii
    $s2 = "#}RiKk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}