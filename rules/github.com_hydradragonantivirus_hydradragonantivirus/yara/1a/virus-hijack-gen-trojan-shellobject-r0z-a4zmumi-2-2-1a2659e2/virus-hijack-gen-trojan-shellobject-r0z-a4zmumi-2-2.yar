rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e1175da432d7b5a994c4c91047f1e39250a95f5430eb1abb6cb1ce8483a76eb"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}