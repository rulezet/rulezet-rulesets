rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b7d52ca84087316b1ea3be33968bdd5c2eac135b7dcddeddc7153377f997e94"

  strings:
    $s1 = "KERN`L32.d" fullword ascii
    $s2 = "Copyright  DhustTrers" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}