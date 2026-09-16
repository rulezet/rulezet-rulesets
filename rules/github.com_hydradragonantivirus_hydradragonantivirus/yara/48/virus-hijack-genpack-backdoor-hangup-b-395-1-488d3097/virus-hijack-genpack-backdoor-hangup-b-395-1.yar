rule Virus_Hijack_GenPack_Backdoor_Hangup_B_395_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_395_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bf1b8bcdf16a7c6ef25621fec8ef386f6e7b7c2dab7be749bdce698a4a3da7f"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "5-b6a0-9baf393cacbc\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}