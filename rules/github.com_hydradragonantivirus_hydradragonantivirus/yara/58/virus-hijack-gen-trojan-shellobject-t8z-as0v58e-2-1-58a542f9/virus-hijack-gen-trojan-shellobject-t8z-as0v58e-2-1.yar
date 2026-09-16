rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b10ef89862a46761370777c0f61a9488cd53816757ba7c91cd92fb1b47dde5c"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}