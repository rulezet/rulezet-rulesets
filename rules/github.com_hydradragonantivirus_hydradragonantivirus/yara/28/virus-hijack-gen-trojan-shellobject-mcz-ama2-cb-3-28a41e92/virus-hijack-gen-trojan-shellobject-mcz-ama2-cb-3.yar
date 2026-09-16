rule Virus_Hijack_Gen_Trojan_ShellObject_mCZ_ama2_Cb_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mCZ@ama2@Cb_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10b85bffbeeec124ed06000f7e3da998b8d82682933460e62386f086aa8ce040"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the so" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}