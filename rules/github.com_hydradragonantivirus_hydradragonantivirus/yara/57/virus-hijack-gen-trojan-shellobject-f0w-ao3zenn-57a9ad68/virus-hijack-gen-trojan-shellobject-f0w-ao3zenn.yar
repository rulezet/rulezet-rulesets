rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e170429b1d08f399281005155067a833b008e57b624c24ac62c437e3d4caff0b"

  strings:
    $s1 = "ZJdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}