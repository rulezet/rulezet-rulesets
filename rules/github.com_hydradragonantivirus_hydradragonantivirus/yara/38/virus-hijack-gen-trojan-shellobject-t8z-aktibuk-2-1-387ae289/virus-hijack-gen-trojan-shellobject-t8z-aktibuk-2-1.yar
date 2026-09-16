rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKTibuk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKTibuk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59380418f3a82b9076b5cc5c326c70a26a2643f0e32c176ecf21231c9053feed"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii
    $s2 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii
    $s3 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}