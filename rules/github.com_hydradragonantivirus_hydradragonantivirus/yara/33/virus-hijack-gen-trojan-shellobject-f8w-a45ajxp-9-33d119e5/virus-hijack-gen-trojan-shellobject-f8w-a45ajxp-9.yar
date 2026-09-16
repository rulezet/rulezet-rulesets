rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a45ajXp_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33a2d31bbcb33c0f66083a6bfa3f2833d93ce5e6b9dcd055855f73f4fdb4abf8"

  strings:
    $s1 = "*hprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "*hprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}