rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aeWgNZc_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aeWgNZc_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb5e3c92c7b4b9eb3b5601d64b54b3a99304ed4399e7068e0dc7c48744a5046"

  strings:
    $s1 = "*juBe?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}