rule Virus_Hijack_Gen_Trojan_ShellObject_zzZ_aCEmdoo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.zzZ@aCEmdoo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d1f1e4fbe88331a528716980fd11d2799d7b495a4a101f23d9e4e7252572707"

  strings:
    $s1 = "PaTHY`C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}