rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f78a8fdebadf3cab02a23312800d50d13c24e2b7ce73a931c3b1247e05999b6e"

  strings:
    $s1 = "uSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}