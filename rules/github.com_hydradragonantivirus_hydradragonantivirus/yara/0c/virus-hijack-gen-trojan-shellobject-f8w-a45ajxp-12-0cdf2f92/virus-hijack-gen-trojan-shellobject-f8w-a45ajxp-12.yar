rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a45ajXp_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bebe287eee24d83fa839ce1c45b4d87969dffccf5b780baa8c02395dc71375a"

  strings:
    $s1 = "Python 3.7." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}