rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5717aced8162bb7b024fc9d8d1643c604484a06baf74460a1248f971b4300fb"

  strings:
    $s1 = "Windows Task Manager" fullword ascii
    $s2 = "Microsoft Windows Spooler" fullword wide
    $s3 = "time e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}