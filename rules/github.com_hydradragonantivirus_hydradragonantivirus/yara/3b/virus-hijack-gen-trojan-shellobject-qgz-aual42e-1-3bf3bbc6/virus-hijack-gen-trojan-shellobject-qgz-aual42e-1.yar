rule Virus_Hijack_Gen_Trojan_ShellObject_qGZ_auAl42e_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.qGZ@auAl42e_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c264c7deb7cca53f7b2362159ec75fd87c8e6e179a788089e81212736f02bf1e"

  strings:
    $s1 = "vAne*9cK" fullword ascii
    $s2 = ")!maTY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}