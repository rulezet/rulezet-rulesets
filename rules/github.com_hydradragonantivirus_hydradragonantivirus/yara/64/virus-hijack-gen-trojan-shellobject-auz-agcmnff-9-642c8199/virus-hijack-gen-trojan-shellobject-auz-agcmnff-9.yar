rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_aGCmnff_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@aGCmnff_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12b80d1d1ca770f9732c1c7e540ff6be7b19197eb2ed31ee2f6f9bc3573939f6"

  strings:
    $s1 = "lush[W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}