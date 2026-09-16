rule Virus_Hijack_Gen_Trojan_ShellObject_nuZ_aOFwKHc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.nuZ@aOFwKHc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db847e9c1ca9aea80725068ab57383a407059b6b4c52ab97cbd9c2b8ea36e186"

  strings:
    $s1 = "TiaO)Mn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}