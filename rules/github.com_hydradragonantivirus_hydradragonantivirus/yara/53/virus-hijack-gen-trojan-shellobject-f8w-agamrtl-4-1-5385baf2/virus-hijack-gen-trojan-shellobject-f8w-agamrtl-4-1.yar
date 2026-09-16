rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb174c9b5f0dba5b79312dc44fb207571ffd21fd3b6631491697f2f818cd4935"

  strings:
    $s1 = "`Object" fullword ascii
    $s2 = "F!Class`." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}