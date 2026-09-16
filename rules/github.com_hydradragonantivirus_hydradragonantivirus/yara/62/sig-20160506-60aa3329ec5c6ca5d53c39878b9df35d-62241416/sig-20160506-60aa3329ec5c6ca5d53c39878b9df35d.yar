rule sig_20160506_60aa3329ec5c6ca5d53c39878b9df35d {
  meta:
    description = "datamaliciousorder - file 20160506_60aa3329ec5c6ca5d53c39878b9df35d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b6e696eee806aedd4934998aa8944c32e5460586a8e6fa54fec28d298bc594"

  strings:
    $s1  = "function tHL(y, cpo){if(\"\" != \"cadaverous\"){bVV = 0xe483;}else{OJC = \"-54346\";}var hA = \"723b546e\";if(hA == \"\"){var Y " ascii
    $s2  = "(03002 == -414){Wr = true;}function Ho1(bXe){return Math.log(bXe);}var Kb = \"60239\";var sx = \"\";if(Kb == sx){var yVS = '-524" ascii
    $s3  = " Math.log(PN);}var GLZ = -1;if(Math.acos(GLZ) === 0){var CL = true;}ylh[V8x]();var JA = \"\";if(JA == \"\\x38\\x38\\x35\\x63\\x6" ascii
    $s4  = "vez = -32383;}else{var Sj = \"\";}var jhP = Math.floor(Math.random() * 65536);var Ib = 0;if(Math.sin(Ib) != 0){nTm = true;}else{" ascii
    $s5  = "f7b95;}var CYh = 0;if(Math.sin(CYh) == 0){lY = \"\";}Z9T = Z9T + 1;var N1 = -1;if(Math.asin(N1) == 0){var Cha = true;}else{var n" ascii
    $s6  = "){xoS = false;}else{nj = '63663';}var UL = RP + \"\\\\\" + jhP + \".\" + M;if(\"cossack\".lastIndexOf(\"47246\") != -1){var lGl " ascii
    $s7  = " i4p = 1;if(Math.sin(i4p) === 0){var pi7 = '';}else{Mr = 'jeffrey';}if(\"2779fda\".lastIndexOf(\"-31882\") != -1){yXE = '2379';}" ascii
    $s8  = " iTc[t].split(\"|\");var kxz = -1;if(Math.sin(kxz) == 0){var Kvh = \"-52155\";}else{var kGe = 0xffffec1d;}var ic = -1;if(Math.co" ascii
    $s9  = "xffff5dc7;}else{eR9 = 077021;}var zC9 = -1;if(Math.sin(zC9) === 0){var eDi = \"57602\";}if(\"\\x61\\x39\\x61\\x62\\x37\\x31\".le" ascii
    $s10 = "-23414){gfB = \"-25936\";}else{Oj = -52075;}ylh[zKn](m);var Hg = 0;if(Math.cos(Hg) >= 0){Dez = \"14162\";}var zRX = -1;if(Math.a" ascii
    $s11 = "7846)){Fz = 0xffff93c7;}else{var I1 = false;}var dlg = -1;if(Math.sin(dlg) > 0){var kR = \"4219\";}var ni = -1;if(Math.asin(ni) " ascii
    $s12 = "\");function tD(wY){return Math.asin(wY);}if(\"0899d01\".length < -13086){yrC = \"\";}else{An = \"-10714\";}var mfx = -1;if(Math" ascii
    $s13 = "\"54654\";var MCK = \"a864104\";if(dL == MCK){jk = false;}function OF(qp){return Math.round(qp);}var fjy = -1;if(Math.cos(fjy) >" ascii
    $s14 = "x34\\x32\\x37\\x31';}var HTF = -1;if(Math.sin(HTF) > 0){var lUl = true;}else{var Pr5 = '\\x31\\x30\\x36\\x64\\x34\\x30\\x35\\x31" ascii
    $s15 = "3\";}var eH = 0;if(Math.sin(eH) >= 0){var GRr = parseInt(-14606);}if(\"-34199\".lastIndexOf(\"-11285\") != -1){uuB = 'da268a';}e" ascii
    $s16 = "= 025447;}else{var tT = \"\";}function kT(Z0){return Math.tan(Z0);}if(\"\".indexOf(\"\") == -1){var HJ = \"e2123c\";}if(\"coloni" ascii
    $s17 = "lse);if(\"\".indexOf(\"principality\") != -1){var gu3 = parseInt(4192);}else{var pK = \"-54951\";}var yT = 1;if(Math.cos(yT) == " ascii
    $s18 = "x) != 0){var hdH = 45093;}else{var KM = \"680ee49\";}var DQ = iE(zY);var X7 = -1;if(Math.sin(X7) === 0){var zT = '\\x65\\x64\\x6" ascii
    $s19 = "parseInt(32999);}function T9(Sa){return Math.tan(Sa);}var H = Jw(\"44420f0533240e5c4059091b36\", \"31lwZTzr\");var ytW = -1;if(M" ascii
    $s20 = " true;}else{zl = 0x4a5e;}var uK = 0;if(Math.sin(uK) != 0){F2 = 31112;}var Ytw = -1;if(Math.sin(Ytw) >= 0){nt = \"adapted\";}var " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}