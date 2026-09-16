rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25db25b783e05c8ab35549ca308f0473a59f42484081b9589677d6572c681865"

  strings:
    $s1  = "CreateSharedMemory() succeeded. mapping obj name:" fullword wide
    $s2  = "ReleaseSharedMemory() succeeded. mapping obj name:" fullword wide
    $s3  = " 2013 Adobe Systems Incorporated.  All rights reserved." fullword wide
    $s4  = "Could not create file mapping object." fullword wide
    $s5  = "MBU Reserved 3" fullword wide
    $s6  = "Osfmui Installer Placeholder1" fullword wide
    $s7  = "Update folder: " fullword wide
    $s8  = "Before RegisterServer" fullword wide
    $s9  = "Office Document Cache (ODC) Client test framework" fullword wide
    $s10 = "FIO Collab Scale Robots" fullword wide
    $s11 = "AUnknown category" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}