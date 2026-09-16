rule sig_20150914_e09ef89ce919249c18b5863b856dbcbd {
  meta:
    description = "datamaliciousorder - file 20150914_e09ef89ce919249c18b5863b856dbcbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33c3d01a096d40b486578556bd58dca2f7cf19db79f3b482414ae4647d1f374a"

  strings:
    $s1  = "var str=\"5550575E060B0300050A240C160A0111160B14014A070B09\";function ip560028() { return 'mentS'; }; function ip1898400() { ret" ascii
    $s2  = "lh=ip202035(); */ function ip484092() { return 'Shell'; }; function ip1214976() { return 'eXO'; }; /* var blh=ip969885(); */ /* " ascii
    $s3  = "* var blh=ip368348(); */ function ip503076() { return 'ar f'; }; function ip1433292() { return '; if '; }; /* var blh=ip900069()" ascii
    $s4  = "* var blh=ip219216(); */ /* var blh=ip353717(); */ function ip569520() { return 'tr'; }; /* var blh=ip956852(); */ /* var blh=ip" ascii
    $s5  = "n 'and'; }; function ip2107224() { return 'reak;'; }; function ip85428() { return 'comm'; }; /* var blh=ip143622(); */ function " ascii
    $s6  = "ip415757(); */ /* var blh=ip573441(); */ /* var blh=ip697288(); */ function ip94920() { return '.sma'; }; /* var blh=ip906767();" ascii
    $s7  = "2.XML'; }; function ip664440() { return 'ode('; }; /* var blh=ip495512(); */ /* var blh=ip829959(); */ /* var blh=ip403318(); */" ascii
    $s8  = "}; function ip1177008() { return ' xa '; }; /* var blh=ip637066(); */ function ip208824() { return 'com l'; }; /* var blh=ip1996" ascii
    $s9  = "+St'; }; /* var blh=ip971642(); */ function ip1499736() { return '= '; }; /* var blh=ip105279(); */ function ip683424() { return" ascii
    $s10 = "nseB'; }; /* var blh=ip494887(); */ /* var blh=ip377212(); */ function ip1594656() { return 'e(fn'; }; function ip1319388() { re" ascii
    $s11 = ") { return 'h.'; }; function ip2059764() { return '}; '; }; function ip2126208() { return '; dl('; }; /* var blh=ip671924(); */ " ascii
    $s12 = "}; /* var blh=ip392675(); */ function ip218316() { return 'es-e'; }; function ip1072596() { return 'eady'; }; function ip702408(" ascii
    $s13 = "734246(); */ /* var blh=ip911421(); */ /* var blh=ip339898(); */ function ip626472() { return 'ring.'; }; function ip730884() { " ascii
    $s14 = " /* var blh=ip923039(); */ function ip797328() { return 'exe\"'; }; /* var blh=ip184797(); */ function ip37968() { return ') { '" ascii
    $s15 = "p28476() { return 'dl(fr'; }; /* var blh=ip498375(); */ /* var blh=ip362527(); */ /* var blh=ip610653(); */ function ip1347864()" ascii
    $s16 = "ion ip1746528() { return 'e('; }; function ip1442784() { return '(xa.'; }; /* var blh=ip627595(); */ function ip436632() { retur" ascii
    $s17 = " ')+'; }; function ip1566180() { return 'av'; }; /* var blh=ip453445(); */ function ip1053612() { return 'f (xo'; }; /* var blh=" ascii
    $s18 = " ip1661100() { return '1,0)'; }; function ip873264() { return 'ew A'; }; /* var blh=ip398926(); */ /* var blh=ip875118(); */ fun" ascii
    $s19 = "ip113904() { return 'lank'; }; /* var blh=ip643948(); */ function ip341712() { return '0; '; }; /* var blh=ip785370(); */ /* var" ascii
    $s20 = " { return 'res'; }; function ip2164176() { return '9172'; }; /* var blh=ip216713(); */ /* var blh=ip858483(); */ /* var blh=ip40" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}