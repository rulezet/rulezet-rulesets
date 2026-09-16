rule Virus_Hijack_GenPack_Backdoor_Hangup_B_290_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_290_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cf791a33adbc7b58b3eefb5bfa05a3dc912b138005bb98545abb6bfcbc3bf48"

  strings:
    $s1  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2  = "olour space - sRGB" fullword ascii
    $s3  = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4  = "e7635808df3\" stEvt:when=\"2019-01-07_19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=" ascii
    $s5  = "7eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windo" ascii
    $s6  = "ters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9" ascii
    $s7  = "7eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windo" ascii
    $s8  = "</rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentI" ascii
    $s9  = "\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a" ascii
    $s10 = "a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:943" fullword ascii
    $s11 = ".IEC 61966-2.1 Default RGB " fullword ascii
    $s12 = "0d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                              " ascii
    $s13 = "png to image/jpeg\"/> <rdf:li stEvt:action=\"derived\" stEvt:param" fullword ascii
    $s14 = "ters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9" ascii
    $s15 = "tID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-03" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}