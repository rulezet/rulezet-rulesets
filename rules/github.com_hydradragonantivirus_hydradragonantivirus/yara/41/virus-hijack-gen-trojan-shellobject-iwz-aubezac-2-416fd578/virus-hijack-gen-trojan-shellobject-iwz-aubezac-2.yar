rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b286315155648c61eb0215446a3e00493e53944e73f8190060cbbfc686b95b3"

  strings:
    $s1 = "!automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}