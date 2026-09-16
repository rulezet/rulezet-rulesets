rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f64f58a506a77528c89b307ad2b912efe85b9ba1b067793252bd1db6a0c6398"

  strings:
    $s1 = "*Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}