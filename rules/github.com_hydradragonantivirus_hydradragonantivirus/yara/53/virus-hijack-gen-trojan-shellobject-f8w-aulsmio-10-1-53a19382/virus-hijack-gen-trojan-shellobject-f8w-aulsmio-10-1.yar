rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63463a610fea5ef1e61f1e1c971eb4f37b7eb96e12371965e7b547c31ecc3574"

  strings:
    $s1 = "!This is a PE executable" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}