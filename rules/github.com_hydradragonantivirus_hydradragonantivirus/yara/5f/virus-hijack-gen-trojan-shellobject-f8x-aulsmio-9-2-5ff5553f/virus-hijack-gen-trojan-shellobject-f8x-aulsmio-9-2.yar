rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6a9e281a6836eed9d5868c4f345cd9aaa0e43a4af02a35cc2c8ee0a2e2696b7"

  strings:
    $s1 = "Could not open regis" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}