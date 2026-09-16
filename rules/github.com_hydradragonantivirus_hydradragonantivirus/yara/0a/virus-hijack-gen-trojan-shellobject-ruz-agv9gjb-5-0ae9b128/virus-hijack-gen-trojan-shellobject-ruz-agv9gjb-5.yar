rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e0097df13fa9d2cd0fca3aba1a691ec16a8ffc24e4a1aed2c8c26ec6214e886"

  strings:
    $s1 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}