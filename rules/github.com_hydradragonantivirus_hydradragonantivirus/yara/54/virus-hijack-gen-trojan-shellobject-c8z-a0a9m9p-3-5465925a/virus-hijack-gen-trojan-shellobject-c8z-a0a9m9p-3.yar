rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "777952b334dda8e8b7ee60ac171e5007a505e03de8d971d56671175ac593ce6a"

  strings:
    $s1 = "RSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}