rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31fbb16252942058628b936a52b8b8bdda88160cc9d882a9475a371374fe1e01"

  strings:
    $s1 = "pOnG'J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}