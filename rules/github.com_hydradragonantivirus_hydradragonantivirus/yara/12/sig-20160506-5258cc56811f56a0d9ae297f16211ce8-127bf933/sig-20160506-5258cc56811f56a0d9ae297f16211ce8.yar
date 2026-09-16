rule sig_20160506_5258cc56811f56a0d9ae297f16211ce8 {
  meta:
    description = "datamaliciousorder - file 20160506_5258cc56811f56a0d9ae297f16211ce8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e51e5a63ed71334055231db934c369d29576b7c8d66469ffb6c632f6ee1f62e2"

  strings:
    $s1  = "function Uaf(kd, IA){if(\"-14577\".indexOf(\"2f3d5280\") == -1){var JA = \"7b12232\";}var kj = -1;if(Math.sin(kj) === 0){eIg = '" ascii
    $s2  = "Cl){return Math.log(oCl);}var wI = \"-55861\";var Me = \"0294208\";if(wI != Me){hR = parseInt(-24775);}var z__ = -1;if(Math.cos(" ascii
    $s3  = "nt(4941);}if(35454 === 0113622){fTD = '31016';}else{Nt = false;}kfa[U](ku, jg, false);function eDL(nb){return Math.log(nb);}var " ascii
    $s4  = "\\x34\\x35\\x65\\x36\\x62\\x31\"){wDD = false;}var NT0 = 0;if(Math.asin(NT0) >= 0){var Wi = '33541';}var au = -1;if(Math.sin(au)" ascii
    $s5  = " UBK + \".\" + dG;function HD(cQT){return Math.floor(cQT);}var hc3 = 1;if(Math.acos(hc3) > 0){dx = '092cdc7';}var VI = -1;if(Mat" ascii
    $s6  = ".sin(eQK) === 0){var Y_ = true;}var L = \"\";if(\"-2388\".length != 0x4bf){var cz = '';}else{yCX = 'daughter-in-law';}var hF9 = " ascii
    $s7  = "9\";}var Yl = 1;if(Math.cos(Yl) > 0){var hX = -10296;}if(\"-57383\".lastIndexOf(\"\\x33\\x32\\x35\\x65\\x38\") == -1){ok = \"631" ascii
    $s8  = "33\".lastIndexOf(\"30285\") == -1){var U9 = '';}var nI = 1;if(Math.cos(nI) >= 0){var D5 = '-8858';}else{y8 = 0xffffe824;}functio" ascii
    $s9  = "(_);var z = \"\";if(z == \"\\x36\\x33\\x37\\x38\"){var a5 = parseInt(72046, 8);}else{UAl = 48393;}var LSD = -1;if(Math.cos(LSD) " ascii
    $s10 = ");}if(\"28114\".lastIndexOf(\"\") == -1){var gg = '';}else{Bbq = '';}var Inz = 1;if(Math.sin(Inz) >= 0){P8a = \"changeable\";}Y[" ascii
    $s11 = "kxN = -1;if(Math.sin(kxN) > 0){var YO = \"-52153\";}else{var GTz = true;}var haq = -1;if(Math.cos(haq) > 0){gu9 = -41625;}var KI" ascii
    $s12 = "(Math.cos(DUs) >= 0){var Gbd = false;}var sb = -1;if(Math.asin(sb) != 0){yh = true;}function oe(md){return Math.tan(md);}if(pars" ascii
    $s13 = "(\"5d4d8\".indexOf(\"\") != -1){uG = false;}else{nQ0 = parseInt(-19688);}return(ni);}function d(){function dO(WtU){return Math.a" ascii
    $s14 = "0xffff0fb7;}var W9t = -1;if(Math.sin(W9t) > 0){BA = '4c651535';}else{var NYL = parseInt(-55808);}L += String.fromCharCode(kd.cha" ascii
    $s15 = "{Tju = parseInt(63401);}var nde = -1;if(Math.cos(nde) === 0){var wn = false;}else{var KX = 35674;}GR[U]();var ZVh = -1;if(Math.a" ascii
    $s16 = "else{Bt = 37414;}var dRA = 0;if(Math.cos(dRA) > 0){Pd2 = '45616';}if(\"5429\".lastIndexOf(\"\") == -1){var vx = true;}var TZ = H" ascii
    $s17 = "038\") != -1){var mw = 33137;}var PM7 = 0;if(Math.cos(PM7) == 0){var iuk = 'a2dfe9c';}var dG = H(\"555416\", \"18z7kWsL\");}else" ascii
    $s18 = "af7\".indexOf(\"\") == -1){KJs = \"f15d33\";}else{HU = -2835;}function DO(W){return Math.exp(W);}var C5J = 0;if(Math.asin(C5J) =" ascii
    $s19 = "-1;if(Math.cos(qd) === 0){p_E = parseInt(-50903);}else{Ahq = '-63377';}if(\"24912\".lastIndexOf(\"\") != -1){XMK = parseInt(3159" ascii
    $s20 = "s = -1;if(Math.sin(as) > 0){fZF = \"fifty-seven\";}var KFF = 1;if(Math.acos(KFF) != 0){APF = 61190;}else{CUh = \"-16941\";}var q" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}