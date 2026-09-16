rule Virus_Infector_Trojan_Agent_DQQD_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.Agent.DQQD_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "866013eedc688814716e91c83f8b38f08a0b0f2abcb04c89bc48b5b25c5f7694"

  strings:
    $s1 = "a88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM:OriginalDocum" ascii
    $s2 = "ID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID" ascii
    $s3 = "a88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM:OriginalDocum" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}