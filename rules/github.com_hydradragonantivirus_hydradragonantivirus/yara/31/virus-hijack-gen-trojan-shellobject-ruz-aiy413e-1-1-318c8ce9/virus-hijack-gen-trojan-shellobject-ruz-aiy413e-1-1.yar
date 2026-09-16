rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e164893f78eb5cd62d8a9e0e8857cfa4a19f54b7530b1d355e04e7b20d555c25"

  strings:
    $s1 = ";taRr`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}