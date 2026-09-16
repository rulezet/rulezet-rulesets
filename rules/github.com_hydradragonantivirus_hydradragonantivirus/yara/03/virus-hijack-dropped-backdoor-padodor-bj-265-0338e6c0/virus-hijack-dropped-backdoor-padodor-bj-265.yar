rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_265 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_265.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23d559ced1517330830d916dd0fea47e478d199c580453d2c44efdddba08dafd"

  strings:
    $s1 = "Microsoft products. You agree that w`" fullword ascii
    $s2 = "COracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}