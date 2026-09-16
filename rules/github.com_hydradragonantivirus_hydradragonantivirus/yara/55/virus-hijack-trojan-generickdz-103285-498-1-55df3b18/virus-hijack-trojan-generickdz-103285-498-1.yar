rule Virus_Hijack_Trojan_GenericKDZ_103285_498_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_498_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0592916eb91377733602f51cef68c23ebd5190b852a27f5771201be81b042e77"

  strings:
    $s1 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}