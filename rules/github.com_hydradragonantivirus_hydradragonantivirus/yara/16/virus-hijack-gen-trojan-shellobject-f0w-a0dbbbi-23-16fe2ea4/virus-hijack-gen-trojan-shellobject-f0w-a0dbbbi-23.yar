rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d152421eeeb4c0aec15019e8b7e0d10c4ddc52432e6d5bae52ee97e5e31cc88"

  strings:
    $s1 = "[1dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}