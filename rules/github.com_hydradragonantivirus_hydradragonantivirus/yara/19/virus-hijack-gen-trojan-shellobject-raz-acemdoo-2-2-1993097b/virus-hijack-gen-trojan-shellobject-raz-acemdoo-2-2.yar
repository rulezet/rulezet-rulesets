rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e483de6608074293fbab08d7a4c32e363dd1b1cbdf168896ca1224ac859c7da9"

  strings:
    $s1  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
    $s2  = " -PS2Load injector v1.0" fullword ascii
    $s3  = " -UsbMCemu injector v1.0-v1.2" fullword ascii
    $s4  = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2014-04-04T22:22:12-03:0" ascii
    $s5  = "! ERROR, no se ha podido completar la operaci" fullword ascii
    $s6  = "Directory entry already added - use MoveDirTo() instead!" fullword ascii
    $s7  = "PS2Load injector v1.2" fullword ascii
    $s8  = "instanceID=\"xmp.iid:BE28F5DAF3BDE31183E48D9726938FD1\" stEvt:when=\"2014-04-06T22:28:54-03:00\" stEvt:softwareAgent=\"Adobe Pho" ascii
    $s9  = "t:instanceID=\"xmp.iid:4B5C3EE55BBCE3119F139FAA3B47F096\" stEvt:when=\"2014-04-04T22:22:12-03:00\" stEvt:softwareAgent=\"Adobe P" ascii
    $s10 = "Error, No se pudo encontrar MSYSTEM.CNF" fullword ascii
    $s11 = "Error: No existe SYSTEM.CNF o esta da" fullword ascii
    $s12 = "Error en SYSTEM.CNF, archivo no legible o en mal estado." fullword ascii
    $s13 = "!ERROR! Aparentemente bien,ISO erroneo(SYSTEM.CNF), no correr" fullword ascii
    $s14 = ") -En terminacion:  Hacker Connection v1.0" fullword ascii
    $s15 = " - Tercer archivo asociado (OTRO)" fullword ascii
    $s16 = "xmp.did:4B5C3EE55BBCE3119F139FAA3B47F096\" photoshop:ColorMode=\"3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\"" ascii
    $s17 = "View TOC (Table of Contents)" fullword ascii
    $s18 = " -Esta version es a pedido de los" fullword ascii
    $s19 = "Table Of Contents" fullword ascii
    $s20 = "n otro soft que logre " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}