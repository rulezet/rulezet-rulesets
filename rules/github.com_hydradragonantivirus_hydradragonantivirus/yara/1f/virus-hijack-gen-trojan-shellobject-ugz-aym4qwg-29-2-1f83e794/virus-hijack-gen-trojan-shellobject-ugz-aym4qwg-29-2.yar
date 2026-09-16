rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_29_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_29_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6629061af862a3780bb17ed9f1f0e9d1ee91a8b6b02e17897cc8f40efce543"

  strings:
    $s1 = "Sync!_C" fullword ascii
    $s2 = "Yellow" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}