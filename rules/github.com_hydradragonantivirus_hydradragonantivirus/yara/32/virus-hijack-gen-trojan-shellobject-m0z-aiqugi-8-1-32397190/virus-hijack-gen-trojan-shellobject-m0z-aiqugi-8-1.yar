rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a506ad502227cba065e319432e71b1689480a3173b02f40138d864f7f009b1"

  strings:
    $s1 = "Java Platform SE Auto Updater" fullword ascii
    $s2 = "Java Update Registration" fullword ascii
    $s3 = "2~ sEmI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}