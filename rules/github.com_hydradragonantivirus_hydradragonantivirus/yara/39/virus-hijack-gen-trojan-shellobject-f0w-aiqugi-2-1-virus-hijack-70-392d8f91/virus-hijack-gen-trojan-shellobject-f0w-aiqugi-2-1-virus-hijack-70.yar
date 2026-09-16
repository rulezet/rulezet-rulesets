rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_2_1_Virus_Hijack_70 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_93_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec37ac989a975bfbe6a5da3573753a326ee660a4bf2d773157c997ae575919e"
    hash2       = "7a3e9e7a19f613af933b2c2755cbc2d6af4516e05656790bb28207f42c728e77"
    hash3       = "80f6adeff8ff98ba5a79e03d03858124102cb2f684913f966792a18882b1fd4e"
    hash4       = "5f2d62f2768019af615b717ecb0a64924642fcd5a53d2db51731525b43ef2113"
    hash5       = "f8942b92be1d51ee6247994cb4307d4b92132ac567e98742018dc8e9e78d1a09"
    hash6       = "983bc0c9ae7db5382e22479d7d971771c5feecd4e3d503dd891549689296f233"
    hash7       = "895eb70ceb98f21f7571958adfb4a3a87846c738cd4be3fac45d49fa2d86de0b"
    hash8       = "a46a03b0b94de02bf5adfbfcfd47b04014fa5dd05b2acb91294b6343f3102905"
    hash9       = "c9665653bb516a7e8ce696224c661c012cfcbd9f1ab8799ef6aa821611f15ec7"
    hash10      = "199967f82f056aa01b622debcaa711cce40b1a5973de99d919e1aff6fcb15368"

  strings:
    $s1  = "ware. These laws include restrictions on destinations, end users and end use. For additional information, see \\hich\\af38\\dbch" ascii
    $s2  = "\\par \\loch\\af38\\dbch\\af31505\\hich\\f38 \\'b7\\tab \\loch\\f38 temporarily download them to a printer or other output devic" ascii
    $s3  = " drive encryption technology may not be as secure as protected content not in a virtualized environment. You should comply with " ascii
    $s4  = " drive encryption technology may not be as secure as protected content not in a virtualized environment. You should comply with " ascii
    $s5  = "\\hich\\af38\\dbch\\af31505\\loch\\f38 www.support.microsoft.com/?kbid=890830\\hich\\af38\\dbch\\af31505\\loch\\f38 . During a M" ascii
    $s6  = "\\hich\\af38\\dbch\\af31505\\loch\\f38 Microsoft provides support services for the software \\hich\\af38\\dbch\\af31505\\loch\\f" ascii
    $s7  = "\\hich\\f38 \\rquote \\loch\\f38 s reporting functionality by following \\hich\\af38\\dbch\\af31505\\loch\\f38 t\\hich\\af38\\db" ascii
    $s8  = ") AND/OR (ii) DECODE AVC, VC-1, MPEG-4 PART 2 AND MPEG-2 VIDEO THAT WAS ENCODED BY A CONSUMER ENGAGED IN A PERSONAL AND NON-COMM" ascii
    $s9  = "cols, which send to the appropriate systems computer information, such as your Internet protocol address, the type of operating " ascii
    $s10 = "certain computer information, such as your Internet protocol address, the type of operating system and browser you are using, an" ascii
    $s11 = "h\\f38 he instructions found at \\hich\\af38\\dbch\\af31505\\loch\\f38 www.support.microsoft.com/?kbid=890830" fullword ascii
    $s12 = "You are not permitted to bypass or circumvent activation.}{\\rtlch\\fcs1 \\af38\\afs20 \\ltrch\\fcs0 \\f38\\fs20\\insrsid4662553" ascii
    $s13 = "You are not permitted to bypass or circumvent activation.}{\\rtlch\\fcs1 \\af38\\afs20 \\ltrch\\fcs0 \\f38\\fs20\\insrsid4662553" ascii
    $s14 = " may install and use the software within only one virtual (or otherwise emulated) hardware system on the licensed computer. When" ascii
    $s15 = "\\hich\\af38\\dbch\\af31505\\loch\\f38 . You may use Remote Assistance or similar technologies to share an active session." fullword ascii
    $s16 = "cols, which send to the appropriate systems computer information, such as your Internet protocol address, the type of operating " ascii
    $s17 = ". The single primary user of the licensed computer may access a session from any other device using\\hich\\af38\\dbch\\af31505" ascii
    $s18 = "ransmission of this information. If properly licensed, you have the right to use the version of the software installed during th" ascii
    $s19 = "\\hich\\af38\\dbch\\af31505\\loch\\f38 www.support.microsoft.com/?kbid=890830\\hich\\af38\\dbch\\af31505\\loch\\f38 . During a M" ascii
    $s20 = "\\par \\loch\\af38\\dbch\\af31505\\hich\\f38 \\'b7\\tab \\loch\\f38 temporarily download them to a printer or other output devic" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}