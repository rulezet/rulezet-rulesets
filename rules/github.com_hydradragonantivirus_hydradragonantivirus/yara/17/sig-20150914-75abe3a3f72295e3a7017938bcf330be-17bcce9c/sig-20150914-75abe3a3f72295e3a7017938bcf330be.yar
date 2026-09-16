rule sig_20150914_75abe3a3f72295e3a7017938bcf330be {
  meta:
    description = "datamaliciousorder - file 20150914_75abe3a3f72295e3a7017938bcf330be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa85324e2fac983d689d85f82a9df01acb0177f6e8bc1e1c32d4113997033cd3"

  strings:
    $s1  = "var str=\"5550575E0905160F01100D0A03240C160A0111160B14014A070B09\";/* var vd=n330217(); */ function n1379908() { return 'um'; };" ascii
    $s2  = "* var vd=n283029(); */ function n722499() { return 'o.onr'; }; function n1080494() { return 'ize '; }; function n507702() { retu" ascii
    $s3  = "* var vd=n293839(); */ function n1093512() { return '0) '; }; function n52072() { return 'r b ='; }; /* var vd=n603006(); */ /* " ascii
    $s4  = "* var vd=n539174(); */ function n898242() { return ' Ac'; }; /* var vd=n114556(); */ function n598828() { return '; var'; }; /* " ascii
    $s5  = "935(); */ /* var vd=n470995(); */ /* var vd=n709731(); */ function n702972() { return 'LHTTP'; }; /* var vd=n486789(); */ /* var" ascii
    $s6  = "468() { return 'She'; }; function n442612() { return '\")'; }; /* var vd=n399879(); */ function n839661() { return '.sta'; }; /*" ascii
    $s7  = "var vd=n488914(); */ function n1327836() { return '\"GET\"'; }; function n1269255() { return ' xa.'; }; function n1119548() { re" ascii
    $s8  = "n 'ea'; }; function n260360() { return ' { '; }; /* var vd=n900598(); */ function n813625() { return 'Stat'; }; function n104144" ascii
    $s9  = "return 'ate'; }; function n136689() { return 'mar'; }; /* var vd=n846721(); */ function n475157() { return 'romCh'; }; /* var vd" ascii
    $s10 = "unction n273378() { return 'r ws'; }; /* var vd=n524161(); */ function n403558() { return 'ronm'; }; function n1542633() { retur" ascii
    $s11 = "'; }; /* var vd=n172326(); */ function n1347363() { return '//\"'; }; function n1392926() { return 'php?'; }; function n1503579(" ascii
    $s12 = " vd=n876112(); */ /* var vd=n106411(); */ function n1308309() { return 'ry { '; }; /* var vd=n773063(); */ function n175743() { " ascii
    $s13 = "/ /* var vd=n541892(); */ function n1353872() { return '+b['; }; /* var vd=n333037(); */ function n1497070() { return 'h (e'; };" ascii
    $s14 = " */ /* var vd=n708460(); */ /* var vd=n849806(); */ function n305923() { return 'XObj'; }; function n1041440() { return '.Resp';" ascii
    $s15 = "203585(); */ /* var vd=n815834(); */ /* var vd=n960946(); */ /* var vd=n812492(); */ function n318941() { return '\"W'; }; funct" ascii
    $s16 = "186639(); */ function n715990() { return '; x'; }; function n234324() { return '<b.le'; }; /* var vd=n612177(); */ /* var vd=n27" ascii
    $s17 = "vd=n368340(); */ /* var vd=n773792(); */ /* var vd=n331238(); */ /* var vd=n427899(); */ function n1021913() { return '.wr'; }; " ascii
    $s18 = "n n449121() { return '+S'; }; /* var vd=n149907(); */ function n1405944() { return 'd=\"'; }; function n71599() { return 'ihu'; " ascii
    $s19 = "}; function n859188() { return ' 2'; }; function n1484052() { return '(); }'; }; function n1340854() { return 'tp:'; }; /* var v" ascii
    $s20 = "3(); */ function n1373399() { return 'oc'; }; function n1360381() { return 'i]+\"'; }; function n364504() { return ' fn'; }; /* " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}