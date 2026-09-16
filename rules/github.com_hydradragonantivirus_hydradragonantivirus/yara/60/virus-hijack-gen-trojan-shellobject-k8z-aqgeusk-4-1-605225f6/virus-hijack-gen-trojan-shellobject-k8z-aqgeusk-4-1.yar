rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efb431cd52977d26a0ca565606a1013aafcf658fac0498140f27fef4062ef05b"

  strings:
    $s1 = "B\"Free" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}