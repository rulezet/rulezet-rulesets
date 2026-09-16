rule Virus_Hijack_Backdoor_Hangup_B_53_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "162e275f23a2728a66d79c382711750583397bab846905663b2530fab7ae4f75"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}