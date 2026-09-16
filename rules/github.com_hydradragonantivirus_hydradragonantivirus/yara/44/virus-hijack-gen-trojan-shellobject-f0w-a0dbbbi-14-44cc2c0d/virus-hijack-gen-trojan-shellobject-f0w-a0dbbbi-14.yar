rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e924ea93435e3612bf038e9bd14243a3d15a9f975ca38ee13994afd319d1671"

  strings:
    $s1 = "hdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}