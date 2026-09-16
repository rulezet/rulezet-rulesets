rule Virus_Hijack_Trojan_Agent_DQQO_227_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14a1ea1ea6c9849fe66eab799c59b60f1605921b1cbe788dd06e091e64305ef"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii
    $s3 = "890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                            " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}