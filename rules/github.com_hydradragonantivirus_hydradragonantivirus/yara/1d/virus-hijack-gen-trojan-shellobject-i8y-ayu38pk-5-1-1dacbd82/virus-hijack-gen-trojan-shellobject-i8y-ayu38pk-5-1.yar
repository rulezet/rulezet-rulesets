rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_ayu38pk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a945360a476dc151f59c5bd4f4518601b1abf1697473c70f02cf8e7011f3a90"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}