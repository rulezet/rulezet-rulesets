rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_479 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_479.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53c964ee3050932a2b06fd11d05f65c35ffea908796e9d4e37a79dc08c06b061"

  strings:
    $s1 = "5active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}