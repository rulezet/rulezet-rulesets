rule sig_19360701_446c88847493ce78b655e517e2a5d081 {
  meta:
    description = "datamaliciousorder - file 19360701_446c88847493ce78b655e517e2a5d081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf93d24f0b8d82a7cc20b99c5d6eb5e5043d6ac66229a80f2d5f965429a55f19"

  strings:
    $s1 = " pre_PayPal0[{o0:'\\u0053'}.o0+{is1:'\\u006c'}.is1+{n0:'\\u0065'}.n0+{nfo3:'\\u0065'}.nfo3+{cc3:'\\u0070'}.cc3](5000);  }  for (" ascii
    $s2 = "    pre_improve10[{ro1:'\\u006f'}.ro1+{c2:'\\u0070'}.c2+{evi0:'\\u0065'}.evi0+{cc3:'\\u006e'}.cc3]({t1:'\\u0047'}.t1+{eol1:'\\u0" ascii
    $s3 = "pre_more={};pre_from7={};pre_law5={};pre_provide7={};pre_varies={};pre_collect7={};pre_believe8={};pre_with={};pre_varies={};pre" ascii
    $s4 = "65'}.n0+{nfo3:'\\u0065'}.nfo3+{cc3:'\\u0070'}.cc3](10000*8);     }   break;  }    };/*sentencesGetting*/;/*bagOf*/;/*little2*/;/" ascii
    $s5 = "freaks10*/;/*just*/;" fullword ascii
    $s6 = "2+{oli1:'\\u006f'}.oli1+{i1:'\\u006f'}.i1+{oti0:'\\u0072'}.oti0]((Math[{he0:'\\u0072'}.he0+{rom2:'\\u0061'}.rom2+{e3:'\\u006e'}." ascii
    $s7 = "u006f'}.oli1+{i1:'\\u006f'}.i1+{oti0:'\\u0072'}.oti0]((Math[{he0:'\\u0072'}.he0+{rom2:'\\u0061'}.rom2+{e3:'\\u006e'}.e3+{ith2:'" ascii
    $s8 = "urn0*/;/*lawyer*/;/*stress1*/;/*file5*/;/*this*/;/*prickIf4*/;/*itself1*/;/*this7*/;/*friends*/;/*least*/;/*least*/;/*this7*/;/*" ascii
    $s9 = "  \\u0066\\u0069\\u006c\\u0065\\u0074\\u0073[{ou2:'\\u0043'}.ou2+{o3:'\\u006c'}.o3+{ro0:'\\u006f'}.ro0+{uc2:'\\u0073'}.uc2+{ro1:" ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}