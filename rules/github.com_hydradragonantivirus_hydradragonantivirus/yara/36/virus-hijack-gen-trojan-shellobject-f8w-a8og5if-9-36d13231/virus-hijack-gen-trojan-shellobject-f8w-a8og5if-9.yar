rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d091ea8fa9c2f870132cfc1aa7f32613864d66e586551eaca96546450b7567b9"

  strings:
    $s1 = "0eby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}