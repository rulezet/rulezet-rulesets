rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "677e745fe7a620336f858b17b60389dd77e399034d2f73d3098042935609d405"

  strings:
    $s1 = "Unsunned" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}