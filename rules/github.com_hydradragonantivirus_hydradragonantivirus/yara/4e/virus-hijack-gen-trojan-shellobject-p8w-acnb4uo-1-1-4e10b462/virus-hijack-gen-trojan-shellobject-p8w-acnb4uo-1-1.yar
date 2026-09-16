rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd04c6ae21a9a63cf3b069cc54c3910b9d4b4e5bb2bd5d27fc416c7d4ecde7ed"

  strings:
    $s1 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}