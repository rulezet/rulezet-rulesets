rule Virus_Hijack_Gen_Trojan_ShellObject_m8X_aW0I0Cd_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8X@aW0I0Cd_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddfaf51b9bc772ba92502fcd630c632c916088ce7426e9c072c14f846d90723"

  strings:
    $s1 = "D}tALe?C" fullword ascii
    $s2 = "OaKy<}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}