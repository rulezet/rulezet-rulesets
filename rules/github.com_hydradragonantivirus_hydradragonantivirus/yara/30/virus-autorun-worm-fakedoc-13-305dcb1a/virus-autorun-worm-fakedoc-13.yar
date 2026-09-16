rule Virus_Autorun_Worm_FakeDoc_13 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d1511ceac3c1cc666bf94fc6d63308c6df450a59352cbb7ec62eb9bc5a3a47f"

  strings:
    $x1  = "This version of Sylfaen supports the WGL4.0 character set, for Pan-European language coverage. In addition to Latin, Greek and C" ascii
    $x2  = "This version of Sylfaen supports the WGL4.0 character set, for Pan-European language coverage. In addition to Latin, Greek and C" wide
    $x3  = " 2010 The Monotype Corporation. All Rights Reserved.Times New RomanRegularMonotype:Times New Roman Regular:Version 5.07 (Microso" ascii
    $x4  = " 2010 The Monotype Corporation. All Rights Reserved.ArialBoldMonotype:Arial Bold:Version 5.06 (Microsoft)Arial-BoldMTArial is a " ascii
    $x5  = " 2010 The Monotype Corporation. All Rights Reserved.ArialRegularMonotype:Arial Regular:Version 5.06 (Microsoft)ArialMTArial is a" ascii
    $x6  = " 2010 The Monotype Corporation. All Rights Reserved.Times New RomanRegularMonotype:Times New Roman Regular:Version 5.07 (Microso" wide
    $x7  = " 2010 The Monotype Corporation. All Rights Reserved.ArialBoldMonotype:Arial Bold:Version 5.06 (Microsoft)Arial-BoldMTArial is a " wide
    $x8  = " 2010 The Monotype Corporation. All Rights Reserved.ArialRegularMonotype:Arial Regular:Version 5.06 (Microsoft)ArialMTArial is a" wide
    $s9  = " embed this font in content as permitted by the embedding restrictions included in this font; and (ii) temporarily download this" ascii
    $s10 = ") embed this font in content as permitted by the embedding restrictions included in this font; and (ii) temporarily download thi" ascii
    $s11 = " (ii) temporarily download this font to a printer or other output device to help print content." fullword ascii
    $s12 = " trademark of The Monotype Corporation.Monotype Type Drawing Office - Robin Nicholas, Patricia Saunders 1982You may use this fon" ascii
    $s13 = "trademark of The Monotype Corporation.Monotype Type Drawing Office - Robin Nicholas, Patricia Saunders 1982You may use this font" ascii
    $s14 = "estrictions included in this font; and (ii) temporarily download this font to a printer or other output device to help print con" ascii
    $s15 = " countries.John Hudson/Geraldine Wadehttp://www.tiro.comYou may use this font as permitted by the EULA for the product in which " ascii
    $s16 = "ft)TimesNewRomanPSMTTimes New Roman is a trademark of The Monotype Corporation.Monotype Type Drawing Office - Stanley Morison, V" ascii
    $s17 = " 2007 Microsoft Corporation. All Rights Reserved.Sylfaen was designed for Microsoft in 1998 by John Hudson and W. Ross Mills of " wide
    $s18 = "This version of Sylfaen supports the WGL4.0 character set, for Pan-European language coverage. In addition to Latin, Greek and C" ascii
    $s19 = "ont stemmed from research into the typographic requirements of many different scripts and languages." fullword ascii
    $s20 = " 2010 The Monotype Corporation. All Rights Reserved.ArialRegularMonotype:Arial Regular:Version 5.06 (Microsoft)ArialMTArial is a" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}