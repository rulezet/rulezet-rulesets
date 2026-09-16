rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6453901b838259e3dccf04504afe8ed8f4554abd79778ac31ed39a756177bff"

  strings:
    $s1 = "whoO{+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}