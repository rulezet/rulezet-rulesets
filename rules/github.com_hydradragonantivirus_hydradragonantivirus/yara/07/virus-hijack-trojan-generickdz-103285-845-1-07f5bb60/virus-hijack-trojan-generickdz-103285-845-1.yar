rule Virus_Hijack_Trojan_GenericKDZ_103285_845_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_845_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df59559b0efb4c04065eb3a134c330fc7d3368dcdd10d7b8bc4a5b515b195ab9"

  strings:
    $s1 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}