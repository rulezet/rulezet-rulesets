rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebabdb04164f59a4db19d586f1e8edcce67661c8ce13d69bc709ecce9caec34e"

  strings:
    $s1 = "w&giRO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}