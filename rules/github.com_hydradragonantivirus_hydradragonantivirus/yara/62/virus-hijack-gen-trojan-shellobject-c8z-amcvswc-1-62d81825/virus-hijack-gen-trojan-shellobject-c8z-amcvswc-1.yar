rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e8a5eb123cd070758f9758ccff402f1583dca89fbe0a76b2dd408534c7db18b"

  strings:
    $s1 = "(fUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}