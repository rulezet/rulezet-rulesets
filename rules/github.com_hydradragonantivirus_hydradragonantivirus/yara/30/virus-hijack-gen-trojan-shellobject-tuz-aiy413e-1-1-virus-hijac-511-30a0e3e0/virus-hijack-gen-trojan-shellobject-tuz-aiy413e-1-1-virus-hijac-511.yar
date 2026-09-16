rule _Virus_Hijack_Gen_Trojan_ShellObject_tuZ_aiy413e_1_1_Virus_Hijac_511 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.tuZ@aiy413e_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_13_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_102_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_127_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18cfcfb7a378e10a39c338a896f5d02325fa6be23584752fcf4e67484f2457b6"
    hash2       = "67273bbfcea369bbe89784511e9b9954c0c42e2a970d6fdca42f46425d447e88"
    hash3       = "1ad1e48a95779c3d74c7e3bb52a9b86464a71a4d8f2b001ff5fe98d5a8424878"
    hash4       = "6b8605e362bac0b9db8328eaf648d7e3ebb1aea84140b1e0c8de07dff2ba5d13"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = "fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEv" ascii
    $s3 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-xyntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
    $s4 = "94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (W" ascii
    $s5 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}