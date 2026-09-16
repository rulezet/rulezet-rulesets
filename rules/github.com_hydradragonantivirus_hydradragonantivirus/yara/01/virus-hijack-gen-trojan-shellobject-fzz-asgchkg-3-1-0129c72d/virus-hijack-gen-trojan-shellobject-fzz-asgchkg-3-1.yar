rule Virus_Hijack_Gen_Trojan_ShellObject_FzZ_aSgChKg_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.FzZ@aSgChKg_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b965aa1eeab51b3da2794567479d289c5ab0682a56290caf4624b8cf77a6e49e"

  strings:
    $s1 = "X4}vaRY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}