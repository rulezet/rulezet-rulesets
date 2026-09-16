rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104_1_Virus_Hija_99 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash2       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash3       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash4       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash5       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"

  strings:
    $s1  = "Copyright (c) 2006-2012, Raph Levien (firstname.lastname@gmail.com), Copyright (c) 2011-2012, Cyreal (cyreal.org)InconsolataRegu" ascii
    $s2  = "LCopyright (c) 2006-2012, Raph Levien (firstname.lastname@gmail.com), Copyright (c) 2011-2012, Cyreal (cyreal.org)InconsolataReg" wide
    $s3  = "<!-- Generator: Adobe Illustrator 19.0.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->" fullword ascii
    $s4  = "    \"\"\"Execute a JSON command and return the result as a dictionary\"\"\"" fullword ascii
    $s5  = "Copyright (c) 2006-2012, Raph Levien (firstname.lastname@gmail.com), Copyright (c) 2011-2012, Cyreal (cyreal.org)InconsolataRegu" ascii
    $s6  = " with a FAQ at: http://scripts.sil.org/OFLhttp://scripts.sil.org/OFL" fullword ascii
    $s7  = "w.cyreal.orgwww.levien.comThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is available" ascii
    $s8  = "E<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s9  = "Z<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s10 = "S<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s11 = "r<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s12 = "l<!DOCTYPE svg  PUBLIC '-//W3C//DTD SVG 1.1//EN'  'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'>" fullword ascii
    $s13 = "   id=\"metadata2\"> Svg Vector Icons : http://www.onlinewebfonts.com/icon <rdf:RDF><cc:Work" fullword ascii
    $s14 = "def cmdj(command):" fullword ascii
    $s15 = "        return importlib._bootstrap.ModuleSpec(fullname, QtResLoader)" fullword ascii
    $s16 = "            raise ImportError(\"get_code() failed\")" fullword ascii
    $s17 = "larRaphLevien,KirillTkachev(cyreal.org): Inconsolata Regular: 2012Version 1.013Inconsolata-RegularCyrealRaph Levien, Kirill Tkac" ascii
    $s18 = "    return json.loads(cmd(command))" fullword ascii
    $s19 = "class QtResLoader:" fullword ascii
    $s20 = "<circle cx=\"2\" r=\"2\" cy=\"2\"/>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}