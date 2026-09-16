rule Virus_Hijack_Trojan_Agent_DQQO_381_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_381_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0703972de52c99eb3034ccf1f9cd7bc318b588194f764c889933f5a30acbe2a5"

  strings:
    $s1 = "<rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}