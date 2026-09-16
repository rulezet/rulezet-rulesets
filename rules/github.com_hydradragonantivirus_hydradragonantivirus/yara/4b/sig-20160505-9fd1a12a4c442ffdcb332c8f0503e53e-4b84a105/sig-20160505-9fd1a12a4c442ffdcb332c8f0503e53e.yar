rule sig_20160505_9fd1a12a4c442ffdcb332c8f0503e53e {
  meta:
    description = "datamaliciousorder - file 20160505_9fd1a12a4c442ffdcb332c8f0503e53e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79865ff585bde1911fa049b997e4f7169a9995c782ca746a04ae3f8d9a508e75"

  strings:
    $x1  = "function pQ(u){if(\"\".lastIndexOf(\"-51142\") < 0){var a = 0xf3f1;}else{var fiS = '';}function Nq0(YUs){return Math.exp(YUs);}i" ascii
    $s2  = "{return Math.log(ls4);}var YvK = -1;if(Math.asin(YvK) === 0){var Ry = '';}else{U2B = '\\x33\\x64\\x39\\x37\\x66\\x31\\x62\\x33';" ascii
    $s3  = "A) != 0){ZSH = false;}var VP = c3 + \"\\\\\" + Opt + \".\" + Tje;var CiW = -1;if(Math.cos(CiW) === 0){p0 = '630393c0';}else{zfi " ascii
    $s4  = "rseInt(52338)){wD5 = true;}var KP = n(\"2c202d\", \"key\");var f1X = -1;if(Math.sin(f1X) != 0){GB_ = \"16612\";}else{k4 = 037777" ascii
    $s5  = "var hF9 = -1;if(Math.cos(hF9) > 0){sod = 'focus';}else{var xD = '';}var PLp = n(\"1811181f100a\", \"key\");var IBK = 1;if(Math.a" ascii
    $s6  = "0f\", \"key\");var iH = 1;if(Math.cos(iH) >= 0){xp = false;}if(\"\\x38\\x63\\x65\\x32\\x34\".length >= -25029){var LEn = \"43637" ascii
    $s7  = "= n(\"04151c05\", \"key\");if(parseInt(-40647) == -62658){var Uax = \"-25281\";}function pzt(QJ){return Math.tan(QJ);}if(0x5d41 " ascii
    $s8  = ", 2)){var sT = \"wetting\";}else{_Gs = 'accommodated';}var dGd = n(\"1c17101f00\", \"key\");if(\"\".indexOf(\"\") != -1){var _N " ascii
    $s9  = "\\x36\\x32\\x61\\x31\\x38\\x38\\x37\") == -1){OnL = parseInt(40915);}var LU = -1;if(Math.sin(LU) >= 0){var cz = '41653';}else{yC" ascii
    $s10 = "}var FMf = 0;if(Math.acos(FMf) === 0){Spd = false;}var WSo = -1;if(Math.cos(WSo) === 0){kLJ = true;}var cK = \"35926\";if(cK == " ascii
    $s11 = " = false;}var rvG = 0;if(Math.cos(rvG) >= 0){gl = \"\";}else{Wh = false;}function gKI(gE){return Math.ceil(gE);}var ngv = -1;if(" ascii
    $s12 = "{var zQl = parseInt(-44905);}var Wn = -1;if(Math.sin(Wn) != 0){sY = '11821';}else{var bg = parseInt(31401, 8);}var T = n(\"18001" ascii
    $s13 = "PLp] == 200){function oyC(SOX){return Math.ceil(SOX);}var zdN = -1;if(Math.cos(zdN) >= 0){bL = false;}var dO = 0;if(Math.asin(dO" ascii
    $s14 = ";}var NMG = 0;if(Math.sin(NMG) >= 0){NHH = 0xffff1b8f;}if(\"-19708\".length == 037777672560){var Af = \"4007\";}var F3_ = -1;if(" ascii
    $s15 = "x33';}else{var xeN = 46628;}var jO6 = -1;if(Math.cos(jO6) === 0){var bDT = '';}if(\"defer\".indexOf(\"26242\") != -1){xcD = true" ascii
    $s16 = ".sin(hr2) != 0){var Nb = 065054;}if(\"94afdfc\".lastIndexOf(\"\\x36\\x34\\x35\\x31\") == -1){SXz = false;}else{FA = '20883';}var" ascii
    $s17 = "58\";}else{var gu = '8478';}var zD = -1;if(Math.asin(zD) > 0){LX = true;}var oq = 1;if(Math.sin(oq) == 0){var Bu = 015146;}var D" ascii
    $s18 = "x38\\x62\\x37\\x34';}var HQ = n(\"191017\", \"key\");if(\"36357\".lastIndexOf(\"-55931\") != -1){var t4 = false;}else{kNi = fals" ascii
    $s19 = "e{eeW = true;}var RdQ = -1;if(Math.acos(RdQ) === 0){var Kv = 12932;}var Tje = n(\"0f0915\", \"key\");}else{var fBS = 0;if(Math.a" ascii
    $s20 = "parseInt(37777777062, 8);}var Koe = -1;if(Math.sin(Koe) == 0){GYZ = \"92b7dfc\";}else{peB = false;}return(y);}Gi1();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}