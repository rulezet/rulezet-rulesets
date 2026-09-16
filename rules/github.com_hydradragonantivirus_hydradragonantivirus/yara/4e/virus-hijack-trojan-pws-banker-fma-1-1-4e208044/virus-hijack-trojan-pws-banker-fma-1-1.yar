rule Virus_Hijack_Trojan_PWS_Banker_FMA_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.PWS.Banker.FMA_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f548bdf661fbb2e9b41416c5fe99c369b52cbdfb2143ae37666d355316b2dd0"

  strings:
    $s1 = "toSy*|" fullword ascii
    $s2 = "l]STeT>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}