rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36ce4dc38c89bf710c77f266ad657147a110ccabe4e42d9f0dfd3d13f4e65886"

  strings:
    $s1 = "/c start \"\" \"%s\" %s" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}