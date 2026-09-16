rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16c901151e7ca86b332ee8c8a6244b23bd9fcd93d05c6443021f995135cfcb2d"

  strings:
    $s1 = ".b***REM Dummy file for NTVDM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}