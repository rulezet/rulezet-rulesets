rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_23_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f185619b109329c80c55dd7d9d4253eded50b5c5bd08158efddc75d9ea33d4"

  strings:
    $s1 = "!8K<Tass" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}