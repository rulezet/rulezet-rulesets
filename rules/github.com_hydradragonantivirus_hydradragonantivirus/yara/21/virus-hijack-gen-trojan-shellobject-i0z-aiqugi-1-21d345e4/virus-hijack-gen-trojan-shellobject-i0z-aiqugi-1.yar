rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "719feb30b836216ca86f0da2827c346783cd5cd2ecb89b88fe8b23bf536886bb"

  strings:
    $s1 = "F4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "LS(sMS(sIS(sIS(sIS(SISH];7I" fullword ascii
    $s3 = "(S('IS(siS('IS(sCS(sIS(sIS(sIS(SISh]-2\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}