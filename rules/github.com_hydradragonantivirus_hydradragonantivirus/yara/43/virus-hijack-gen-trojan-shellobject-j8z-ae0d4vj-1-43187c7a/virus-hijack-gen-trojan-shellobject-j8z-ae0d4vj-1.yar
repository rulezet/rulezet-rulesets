rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712c7fda308a42fb5e7717d2f79d94f4fa8f236c811b785b3d4df82175b7f7cb"

  strings:
    $s1 = "Ua neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii
    $s2 = "E<sOho" fullword ascii
    $s3 = "dISS`g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}