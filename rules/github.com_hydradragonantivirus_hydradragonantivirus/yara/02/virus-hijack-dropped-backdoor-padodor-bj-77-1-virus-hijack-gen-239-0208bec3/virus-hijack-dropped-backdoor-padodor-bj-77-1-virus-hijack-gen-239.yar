rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_77_1_Virus_Hijack_Gen__239 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_77_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2467cac4e72e1e7b244a0d73142dd174539a8b667831b4eac54d489522e74b6e"
    hash2       = "d08c7f4e1036eb1580a255e16a8cf72c8fa4b374b3ab7545267dcd8d3a8a9fae"
    hash3       = "d779e1b9b965342481f87fc756c097f891ad2a68cc697dba97e17a3eff5524b9"

  strings:
    $s1 = "_tWinMain (Ship) commandline='%s'" fullword ascii
    $s2 = "GetOffice type for '%S'" fullword ascii
    $s3 = "not found by GetOfficeType" fullword ascii
    $s4 = "not found in CreateInstanceEnumAsync" fullword ascii
    $s5 = "Office Data Provider for WBEM" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}