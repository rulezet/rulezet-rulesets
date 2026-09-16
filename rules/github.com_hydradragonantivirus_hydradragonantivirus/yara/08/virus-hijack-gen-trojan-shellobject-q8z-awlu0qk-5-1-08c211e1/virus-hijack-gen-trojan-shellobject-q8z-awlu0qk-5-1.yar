rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d1bee220c0fb7f618878006c9ed91c6b50337e5194463cff9c4b69618fc0cd5"

  strings:
    $s1 = "9:tarE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}