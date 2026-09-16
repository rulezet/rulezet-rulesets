rule sig_20160506_f0c01e7fb730ccc345e54a246428cf9d {
  meta:
    description = "datamaliciousorder - file 20160506_f0c01e7fb730ccc345e54a246428cf9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a6e8df956e41418e878bc3973054b3337dda15ecc63776715f29da9a0d0a878"

  strings:
    $s1  = "function Bu(WQ, k1h){var _qT = 1;if(Math.asin(_qT) == 0){Csd = \"diphtheria\";}var IF = -1;if(Math.cos(IF) != 0){var f = '456c9c" ascii
    $s2  = "function yyD(guL){return Math.log(guL);}if(\"9891\".lastIndexOf(\"\\x33\\x39\\x34\\x34\\x37\\x33\\x61\\x61\") != -1){FAh = '-334" ascii
    $s3  = ".ceil(qT);}var kdh = \"5068\";var I9 = \"-62564\";if(kdh === I9){var L8n = false;}else{m6 = true;}function _Je(kH){return Math.l" ascii
    $s4  = "Kp = \"-46551\";}function em(Hny){return Math.log(Hny);}var u8a = 0;if(Math.cos(u8a) > 0){var zr = \"\\x31\\x63\\x63\\x33\\x61" ascii
    $s5  = "H);}function uvu(sC){return Math.log(sC);}var Zyj = \"funnel\";var V3 = \"\";if(Zyj == V3){ds = parseInt(-35307);}var iBv = ZM(" ascii
    $s6  = "Math.sin(skL) === 0){lL = \"\";}if(\"\".lastIndexOf(\"botany\") == -1){var fo = -58553;}else{Wk_ = parseInt(156276, 8);}if(\"830" ascii
    $s7  = "ath.acos(GAo);}var vtz = -1;if(Math.cos(vtz) == 0){mc = 15117;}if(\"\".length <= 6879){tk = '-14950';}else{var vae = parseInt(-2" ascii
    $s8  = "ar uET = Math.floor(Math.random() * 65536);if(\"21413\".length == -24908){LX9 = -6772;}else{YXe = \"29787\";}var tbb = \"-18145" ascii
    $s9  = "715';}var BM = 1;if(Math.sin(BM) > 0){gL = parseInt(8498);}var T1h = new Array();var vce = -1;if(Math.cos(vce) > 0){var gwd = '3" ascii
    $s10 = "se{var ChF = false;}function CpE(IbC, ZKd){return Math.atan2(IbC, ZKd);}var Oe = -1;if(Math.sin(Oe) == 0){var r1g = \"\\x64\\x39" ascii
    $s11 = "TLi = true;}var mE5 = 1;if(Math.cos(mE5) > 0){AIE = \"47237\";}return ha;}function kP(){var tT = -1;if(Math.asin(tT) >= 0){fBS =" ascii
    $s12 = "ue;}var taX = -1;if(Math.cos(taX) != 0){Lsi = false;}else{var ZI = \"24826\";}var xQT = ZM(\"2d363d59\", \"BFX7HTd\");var skL = " ascii
    $s13 = ");}var UE = -1;if(Math.sin(UE) >= 0){var lh1 = true;}if(parseInt(-57611) > 28267){WBR = 4625;}else{Mz = \"-14343\";}var dr = 1;i" ascii
    $s14 = "sun\";}else{TYf = -25755;}var RZe = 0;if(Math.cos(RZe) > 0){var umF = 0110524;}else{var OiT = \"24103\";}function C7(xQ){return " ascii
    $s15 = "ue;}var P1p = parseInt(sHX[2]);var gXS = -1;if(Math.sin(gXS) >= 0){var kJ = true;}else{var ue2 = parseInt(-53857);}var Rcv = -1;" ascii
    $s16 = "7\\x37\\x39\\x30\";}var ZjY = 0;if(Math.acos(ZjY) == 0){vg = true;}var sHX = J3y[i].split(\"|\");var uJN = -1;if(Math.sin(uJN) >" ascii
    $s17 = "function b2(Ukm){return Math.cos(Ukm);}var ZVX = \"\";if(ZVX == \"48993\"){var y4y = \"cdabdc\";}else{var F_Q = -16352;}if(parse" ascii
    $s18 = " -5075){var HbY = 0xcdad;}var XY = -1;if(Math.sin(XY) === 0){i8 = 016076;}else{io = '640db';}if(\"condos\".length != -20804){wE " ascii
    $s19 = "r A7 = -1;if(Math.cos(A7) > 0){KJ = 17756;}else{var Bqa = false;}if(parseInt(-47864) > parseInt(156156, 8)){var ct = \"buried\";" ascii
    $s20 = "}else{avd = true;}var wNM = \"\";if(wNM === \"\"){OTG = -24716;}var q2 = ns[ELD].substr(0, 2);function ce2(X3S){return Math.abs(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}