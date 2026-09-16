rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48e1b20189902cd4b782640ab9b9d1556e3e6b89b6c816bc930bf1f4680e11bb"

  strings:
    $s1 = "CoaT(li" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}