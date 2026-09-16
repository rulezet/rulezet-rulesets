rule VirusShareTrojanSiggen1528917 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1528917.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebfd81a0a59217653b8218f3a673292fa9b31891e3b1055b8779f384e7f2b021"

  strings:
    $s1  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
    $s2  = "oBjladMPXt8YYv0yNb.GGpAQWR5kmXUFYWcRM+BmrnRfGSnvi4k1R1Ns+r2nqrrib92xu5Efu00`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s3  = "67\" xmpMM:InstanceID=\"xmp.iid:A89D13EE5B5C11E0B62CC50EE94CE567\" xmp:CreatorTool=\"Adobe Photoshop CS5 Windows\"> <xmpMM:Deriv" ascii
    $s4  = "    <li command=\"richtext:paste-html-no-tables\">Paste without tables</li>" fullword ascii
    $s5  = "    <li command=\"richtext:paste-text-as-html\">Paste text as HTML</li>" fullword ascii
    $s6  = "        <li command=\"richtext:paste-plain-text\">Paste text only</li>" fullword ascii
    $s7  = " Copyright (C) 2010, International Business Machines Corporation and others. All Rights Reserved. " fullword ascii
    $s8  = "<Module>{1E63CF17-325F-4097-9E99-8A977BE1F766}" fullword ascii
    $s9  = "<menu .richtext-context>" fullword ascii
    $s10 = "  <li>Paste special" fullword ascii
    $s11 = "AO Filing Lab" fullword wide
    $s12 = "Filing helper" fullword wide
    $s13 = " 2017 AO Filing  Lab. All Rights Reserved." fullword wide
    $s14 = "Filing Anti-Virus" fullword wide
    $s15 = "  >Select All<span class=\"accesskey\">Ctrl+A</span></li>" fullword ascii
    $s16 = "  >Split by rows<span class=\"accesskey\">Ctrl+1</span></li>" fullword ascii
    $s17 = "  >Paste<span class=\"accesskey\">Ctrl+V</span></li>" fullword ascii
    $s18 = "  >Copy<span class=\"accesskey\">Ctrl+C</span></li>" fullword ascii
    $s19 = "  >Cut<span class=\"accesskey\">Ctrl+X</span></li>" fullword ascii
    $s20 = "  >Split by columns<span class=\"accesskey\">Ctrl+2</span></li>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}