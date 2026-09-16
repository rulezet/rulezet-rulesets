rule Virus_Hijack_Trojan_GenericKDZ_103285_214_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_214_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a41821b193c6177cf99630e2d4bc4730226576ce6f5ede99e35808b1d5aa77f"

  strings:
    $s1 = "s=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}