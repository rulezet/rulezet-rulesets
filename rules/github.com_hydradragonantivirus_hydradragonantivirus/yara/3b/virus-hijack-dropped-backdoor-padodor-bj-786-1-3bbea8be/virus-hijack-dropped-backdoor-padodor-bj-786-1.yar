rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_786_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_786_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4569225c4f016ca095ab9020aafb5086634c041871c82aedbac2ad4bba176dd1"

  strings:
    $s1 = "jointuress" fullword wide
    $s2 = "wheelrace" fullword wide
    $s3 = "griffonage" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}