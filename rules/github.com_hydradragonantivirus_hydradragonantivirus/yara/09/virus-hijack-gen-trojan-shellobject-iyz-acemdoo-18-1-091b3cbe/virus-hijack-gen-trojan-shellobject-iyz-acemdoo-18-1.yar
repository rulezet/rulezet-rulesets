rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3d1c875280916ac249cfcbf2c04c6b77eb2d66430137d22190df9f01a280471"

  strings:
    $s1 = "**** Error 0x%x returned by CertFindCertificateInStore" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}