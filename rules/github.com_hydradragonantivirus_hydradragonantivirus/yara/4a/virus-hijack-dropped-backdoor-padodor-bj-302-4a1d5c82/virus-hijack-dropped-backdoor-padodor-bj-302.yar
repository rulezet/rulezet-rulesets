rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_302 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_302.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c6f9bd70770ec89fdb7116cefe33138f1dd167260b7e0c44e6769c8d4b335fa"

  strings:
    $s1 = "@prevent either party from disclosing the terms o" fullword ascii
    $s2 = "$%ceLL" fullword ascii
    $s3 = "$&ceLL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}