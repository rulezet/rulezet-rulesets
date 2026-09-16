rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aeWgNZc_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aeWgNZc_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c105f71b2173e0f559449a1ff6bdda189776714ad7883a2630e48f50bf79c608"

  strings:
    $s1 = ":bABa$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}