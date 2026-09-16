rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "122a168728843f5c6ea4b9a93615931ed6546a97f808892de28fa6b9e80a4e69"

  strings:
    $s1 = "Vdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}