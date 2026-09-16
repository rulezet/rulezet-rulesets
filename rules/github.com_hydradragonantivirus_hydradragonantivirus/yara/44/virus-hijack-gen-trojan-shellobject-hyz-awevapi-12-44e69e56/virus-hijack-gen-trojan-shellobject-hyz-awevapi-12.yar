rule Virus_Hijack_Gen_Trojan_ShellObject_hyZ_aWevApi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hyZ@aWevApi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c3bff3e87a28159de356fce701fa513586364ec818202556e23a84f1b1196a"

  strings:
    $s1 = "sadr#N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}