rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a276d252f4edcef471894a6bfc4b852ce83f6dc137a8ffa361ae89d3af4c348"

  strings:
    $s1 = "hafF&a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}