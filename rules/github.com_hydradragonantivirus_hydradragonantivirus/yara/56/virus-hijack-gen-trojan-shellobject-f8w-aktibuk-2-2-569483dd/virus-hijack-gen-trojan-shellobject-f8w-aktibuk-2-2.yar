rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKTibuk_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKTibuk_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b66ffee541621a7c74dfdd9fd7917e57cd42e4a1260e93079098a4032a3773"

  strings:
    $s1 = "oNUS \"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}