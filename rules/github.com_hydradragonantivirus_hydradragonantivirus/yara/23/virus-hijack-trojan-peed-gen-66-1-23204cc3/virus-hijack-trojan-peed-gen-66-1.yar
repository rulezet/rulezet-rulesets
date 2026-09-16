rule Virus_Hijack_Trojan_Peed_Gen_66_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af5489ffdfd65932677045fa1cc63daeee6f11726a537f3fc36aafc70b407350"

  strings:
    $s1 = "sLUR *" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}