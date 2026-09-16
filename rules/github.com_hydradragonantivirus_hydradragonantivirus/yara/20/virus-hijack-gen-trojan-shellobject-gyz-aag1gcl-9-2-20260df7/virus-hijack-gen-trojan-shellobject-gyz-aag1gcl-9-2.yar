rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9159d67d4b10761d9ea83106c0275a567904e111d78bbfc15f4e198d4cb4069f"

  strings:
    $s1 = "Microsoft Office Document Cache Migration" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}