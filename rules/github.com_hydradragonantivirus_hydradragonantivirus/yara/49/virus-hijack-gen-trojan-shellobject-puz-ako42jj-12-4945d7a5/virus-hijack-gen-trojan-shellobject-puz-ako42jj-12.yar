rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "687047f6ff2da4b5a8a0489d848abe84eeb841de9ce30769be8eb965a632d9e5"

  strings:
    $s1 = "WHau%2g" fullword ascii
    $s2 = "k>bond" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}