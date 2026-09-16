rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7327d8a6011b4fe417c8232e3481688a27accd88cec9a4f217de9bcdbba8c0d0"

  strings:
    $s1 = "!That program cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}