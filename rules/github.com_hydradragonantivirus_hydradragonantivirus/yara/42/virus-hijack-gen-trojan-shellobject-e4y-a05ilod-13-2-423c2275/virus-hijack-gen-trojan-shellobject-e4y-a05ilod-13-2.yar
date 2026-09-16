rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb015228e3dae8caeb1e2909a4e7c45a8e55fab5ef706bfb92364e216f1ca46f"

  strings:
    $s1 = "pOnG'J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}