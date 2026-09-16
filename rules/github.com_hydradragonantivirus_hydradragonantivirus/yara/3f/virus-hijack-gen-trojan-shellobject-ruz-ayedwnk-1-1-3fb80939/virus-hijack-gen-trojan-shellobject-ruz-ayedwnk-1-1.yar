rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_ayeDwnk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@ayeDwnk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eccd5fca8f3529dbb754f4330636a8fb8788803e02e08af8661f03517a48d7c2"

  strings:
    $s1 = "''PITa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}