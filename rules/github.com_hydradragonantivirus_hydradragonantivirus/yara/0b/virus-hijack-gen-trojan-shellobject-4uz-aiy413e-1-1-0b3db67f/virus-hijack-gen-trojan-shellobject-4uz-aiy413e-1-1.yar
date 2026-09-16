rule Virus_Hijack_Gen_Trojan_ShellObject_4uZ_aiy413e_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4uZ@aiy413e_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f2e679547881ddbb3464cd5023e8504d0a0f4d5814a1821ff3e2823477878e4"

  strings:
    $s1 = "convert to a perpetual license. If you extend your subscription, you may continue using th" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}