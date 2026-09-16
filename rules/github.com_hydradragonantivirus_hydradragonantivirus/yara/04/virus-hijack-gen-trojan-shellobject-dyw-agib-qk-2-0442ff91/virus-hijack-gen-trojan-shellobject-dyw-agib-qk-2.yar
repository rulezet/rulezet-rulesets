rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aGIb_Qk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aGIb!Qk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03fd14227baa04c172e1bb0b8200ce58dfdd57168d74d43ebfe7c2e5fbef0d8b"

  strings:
    $s1 = "SI`Lowa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}