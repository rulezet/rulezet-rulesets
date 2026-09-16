rule Virus_Hijack_Trojan_Agent_DQQO_356_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_356_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48cd4dd8ec82d54526162882d49e8d931d0048632c286697ea08ded54c91a073"

  strings:
    $s1 = "8:00\"`stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda" ascii
    $s2 = "<rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}