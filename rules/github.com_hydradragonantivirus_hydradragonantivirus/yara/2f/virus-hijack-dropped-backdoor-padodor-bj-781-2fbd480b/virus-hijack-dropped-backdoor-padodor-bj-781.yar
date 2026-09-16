rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_781 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_781.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92972e05df3ec73d920d6b37b8bcc100c258e7b16a1ba347484f7b28c69438ba"

  strings:
    $s1 = "ZYou may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}