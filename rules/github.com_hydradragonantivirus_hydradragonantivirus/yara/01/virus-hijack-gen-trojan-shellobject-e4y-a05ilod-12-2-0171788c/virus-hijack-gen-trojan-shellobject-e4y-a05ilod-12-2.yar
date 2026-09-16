rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0f57b36ac081f5302c68cf2914d53bda859e727cc8ca266ed4dc6339dd28311"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}