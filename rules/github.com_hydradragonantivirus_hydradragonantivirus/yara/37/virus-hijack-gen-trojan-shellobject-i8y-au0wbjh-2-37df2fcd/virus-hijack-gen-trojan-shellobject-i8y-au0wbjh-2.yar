rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e0cc3ba21e3feeef4481d6f4b5cd53e704af4fc7ffb1d0a39e81e432db22fba"

  strings:
    $s1 = " orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}