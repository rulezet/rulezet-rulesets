rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKTibuk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKTibuk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a66a1eb26008b4376575ae9630c99c869b3b25d9523b0e34a81730d0d606c363"

  strings:
    $s1 = "h@xd(maCO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}