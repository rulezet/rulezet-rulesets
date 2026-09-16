rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f112b9361ab5e0c9da12e2356e3144ba9dd35aac9cfd7e700f23131ac1df6315"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}