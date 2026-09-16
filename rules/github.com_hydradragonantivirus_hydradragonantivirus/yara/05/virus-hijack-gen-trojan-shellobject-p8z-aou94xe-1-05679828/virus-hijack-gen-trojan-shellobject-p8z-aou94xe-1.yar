rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_aOU94xe_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aOU94xe_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62954fdf65e629b39a29f539619d20691332184c6b6be5a826128a8e759bfa84"

  strings:
    $s1 = " v3.58 beta" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}