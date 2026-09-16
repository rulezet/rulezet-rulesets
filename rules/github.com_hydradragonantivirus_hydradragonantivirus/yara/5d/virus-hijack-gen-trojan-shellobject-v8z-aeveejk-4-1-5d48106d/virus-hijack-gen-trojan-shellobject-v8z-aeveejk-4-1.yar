rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_aeVeeJk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aeVeeJk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a8e9d87005a9c17745be3446dc68e80272d651db65b72f29a31cd8c0a2fb1a9"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii
    $s3 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}