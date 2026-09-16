rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29482dc5c388f70aa2dea2a1012eb29b7cb25a1977e6499bf95067a76f76f44a"

  strings:
    $s1 = "kernel)V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}