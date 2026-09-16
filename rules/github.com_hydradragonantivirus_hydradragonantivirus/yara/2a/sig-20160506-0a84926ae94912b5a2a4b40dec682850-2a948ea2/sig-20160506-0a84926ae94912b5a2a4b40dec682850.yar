rule sig_20160506_0a84926ae94912b5a2a4b40dec682850 {
  meta:
    description = "datamaliciousorder - file 20160506_0a84926ae94912b5a2a4b40dec682850.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8feff5ef4168b73e7b6abb865d9468d476eb25e459efabe1ab279f25ccb3c85d"

  strings:
    $s1  = "function POj(){var XOa = 0;if(Math.sin(XOa) === 0){var AGt = 0x3c02;}else{var ahI = \"\\x36\\x61\\x64\\x36\\x38\\x65\\x39\";}fun" ascii
    $s2  = "ssay\";}else{var zi = true;}var Rlc = k(\"17241d181d61542f081919270e27\", \"zWeuqS\");function Lu(eA){return Math.log(eA);}var N" ascii
    $s3  = ".log(Lp);}function G3g(HWN){return Math.sqrt(HWN);}if(0xcb10 < parseInt(25297)){Su2 = \"\\x32\\x39\\x61\\x63\";}yw[KK]();var hcZ" ascii
    $s4  = " = parseInt(37777712607, 8);}function a59(Mi){return Math.log(Mi);}if(\"\".length > 037777771211){npF = \"\";}var CK = new Activ" ascii
    $s5  = "Lnk){return Math.log(Lnk);}try{v = parseInt(122052, 8);}catch(oSd){PY = '\\x31\\x31\\x62\\x30\\x31\\x62\\x64';}finally{var c = p" ascii
    $s6  = "\".\" + ed;if(037777715553 == 16569){var ogI = '8607ff19';}else{var neW = true;}if(\"29188\".length == -26182){aBr = '';}if(\"" ascii
    $s7  = "\"\";if(WR == \"52193\"){var WtU = parseInt(4061);}else{Zwm = 0xffff5410;}var qh = -1;if(Math.cos(qh) >= 0){var Rx = 'nashville'" ascii
    $s8  = "}else{var CnH = 0xffff6fec;}if(\"bullying\".lastIndexOf(\"-4231\") > 0){var Kme = 12590;}var Me = 1;if(Math.cos(Me) == 0){yVc = " ascii
    $s9  = "ar aS = 'dinghy';}else{lW = false;}for(var CqC = 0; CqC < ig.length; CqC += 2){var uGr = -1;if(Math.cos(uGr) >= 0){var D8C = 'de" ascii
    $s10 = "1 = false;}var KHs = x[0];var lo = -1;if(Math.sin(lo) === 0){var qHI = true;}else{rQT = \"jocular\";}if(\"\".lastIndexOf(\"\") <" ascii
    $s11 = "= parseInt(37777734241, 8)){var YQ = \"16984\";}else{var snK = true;}var _g = -1;if(Math.sin(_g) === 0){Ljm = \"64736\";}else{Fl" ascii
    $s12 = "r jNj = -1;if(Math.sin(jNj) === 0){NDE = 0x54bc;}var ncE = k(\"2d083f35\", \"YqOPuf\");if(parseInt(48359) <= 0xb065){SJ = true;}" ascii
    $s13 = ".exp(TLi);}if(\"twirl\".indexOf(\"\") != -1){var SG = '31926';}else{var Hdn = \"\";}var HWG = 0;if(Math.sin(HWG) != 0){var kKk =" ascii
    $s14 = "\"\";}var o = o.split(\",\");var VO = -1;if(Math.cos(VO) > 0){C = 0x3a8c;}if(parseInt(37777654175, 8) == 037777706345){var H = f" ascii
    $s15 = "unction J(ig){var g_B = -1;if(Math.sin(g_B) > 0){yin = parseInt(-44863);}else{MH = \"0b1a980\";}var mqQ = 1;if(Math.sin(mqQ) > 0" ascii
    $s16 = "';}if(59944 >= -39516){var XBY = 0xffff8b55;}else{btF = false;}var o6d = du(ig, VD);var aQt = -1;if(Math.cos(aQt) > 0){RsX = \"s" ascii
    $s17 = ", 2), 16));}var b2 = 1;if(Math.sin(b2) === 0){var _YD = \"-9279\";}else{var gEH = -42673;}if(037777771772 > parseInt(47200)){var" ascii
    $s18 = "lastIndexOf(\"these\") > 0){var tJ = 0xffff4c1d;}var fRR = -1;if(Math.cos(fRR) === 0){PPf = true;}try{var CN = parseInt(175266, " ascii
    $s19 = "Of(\"\") < 0){var F = true;}if(037777726132 <= -49958){QZD = '-29035';}function AA(dB){return Math.sin(dB);}if(-33032 >= parseIn" ascii
    $s20 = "-36185)){var jd = 64951;}else{BF = parseInt(-35667);}function gSa(rE){return Math.acos(rE);}var JO = -1;if(Math.sin(JO) === 0){v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}