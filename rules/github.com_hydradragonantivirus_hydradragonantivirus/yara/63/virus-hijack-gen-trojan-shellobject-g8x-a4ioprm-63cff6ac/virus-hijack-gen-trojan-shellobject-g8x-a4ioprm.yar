rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_a4IOpRm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@a4IOpRm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b44414753fb39300478eb89d9025620f41d966261f3a50bc219b2e4eb0e1465"

  strings:
    $s1 = "Fyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}