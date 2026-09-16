rule Virus_Hijack_Trojan_GenericKDZ_103285_308_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7868cd73ba5690cd1585b48d2defb1b05ab868aa5845e23aca0a803d9b61b0ea"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii
    $s3 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}