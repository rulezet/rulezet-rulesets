rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3ccf65303a7efbbfcfb3b14e19841af015a7652995176e1c96a1d09b4ef967b"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}