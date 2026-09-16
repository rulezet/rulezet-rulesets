rule sig_20160505_58bddc12fb2e77be7f28a82308e50066 {
  meta:
    description = "datamaliciousorder - file 20160505_58bddc12fb2e77be7f28a82308e50066.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8288589414b9ce67f5d80f2815704584ae824c271dda20605a40c58b1c5c6a9"

  strings:
    $x1  = "function j(AS_, LaC){if(042744 === 033600){Nt = false;}else{var SRL = \"41323\";}if(\"\".lastIndexOf(\"8d235536\") == -1){var a8" ascii
    $s2  = "{CC = -61651;}var QG = 0;if(Math.acos(QG) === 0){var Uk = parseInt(-44972);}else{oP = 0xc189;}function hA(zJ){return Math.log(zJ" ascii
    $s3  = "x32\\x36\\x65\\x37';}else{UFN = true;}function FMf(EJ){return Math.log(EJ);}var NN = M(\"0a01160f075718110b0e0414\", \"key\");va" ascii
    $s4  = "h.log(Rf);}function pB(fW){return Math.exp(fW);}if(parseInt(1100001101101011, 2) != 10695){y2c = false;}else{P9 = '';}var ia = i" ascii
    $s5  = "sin(U5) == 0){var iO3 = '\\x33\\x63\\x38\\x66\\x39';}else{var NK = \"\";}if(\"pipe\" == \"-64422\"){Zu8 = false;}var _q = -1;if(" ascii
    $s6  = "Math.floor(yVc);}var n = ia[EYg].split(\"|\");if(\"\".length <= parseInt(12295)){var RK = false;}var toC = -1;if(Math.cos(toC) !" ascii
    $s7  = "eInt(11111111111111111111001101110110, 2) <= -46137){oRU = -21892;}else{KEK = \"-34769\";}var Jw = -1;if(Math.cos(Jw) == 0){var " ascii
    $s8  = "\\x30\\x35\\x61\") != -1){var L = true;}function z(c_K){return Math.tan(c_K);}if(\"-27956\".indexOf(\"-31298\") > 0){_b = parseI" ascii
    $s9  = "\\x64\";}var rff = 1;if(Math.asin(rff) == 0){var Sng = parseInt(19615);}var dj0 = -1;if(Math.cos(dj0) >= 0){GE = 075723;}else{va" ascii
    $s10 = "if(Math.cos(mQ) > 0){Lsi = false;}if(0x6589 > parseInt(1110100001101101, 2)){var GD = \"32b87\";}else{fJ5 = \"ordered\";}Az = Az" ascii
    $s11 = "(\"0809161800\", \"key\");if(\"99cc038\".lastIndexOf(\"detailed\") != -1){var hI = parseInt(-13179);}else{Zb = 28320;}var S1g = " ascii
    $s12 = "c321\") > 0){pTG = true;}else{cz = '-35765';}var hJ = M(\"1811181f100a\", \"key\");var B0S = -1;if(Math.acos(B0S) == 0){_l = '8e" ascii
    $s13 = "var od = -1;if(Math.asin(od) >= 0){_gn = 'migrate';}else{ZP = true;}var b2 = -1;if(Math.sin(b2) == 0){var Sl = '-30162';}var Az " ascii
    $s14 = "1;}var D3D = -1;if(Math.cos(D3D) != 0){var Nuj = \"bd69\";}if(parseInt(34342) < -32436){V7 = \"mysql\";}function sH(fI){return M" ascii
    $s15 = "eInt(-60650)){vg = true;}if(\"land\".indexOf(\"-40119\") != -1){Ltp = '\\x31\\x37\\x36\\x61\\x32\\x36\\x39';}var FQ = M(\"0e1d1c" ascii
    $s16 = "Wdr = parseInt(-64330);}else{var wKS = \"\\x66\\x39\\x65\\x34\\x35\\x38\\x66\\x62\";}var Bt = -1;if(Math.cos(Bt) != 0){var Yth =" ascii
    $s17 = "yrC = -1;if(Math.cos(yrC) != 0){JvO = \"68cd\";}if(parseInt(37777647772, 8) <= 47908){YW = false;}else{var F1q = \"14473\";}var " ascii
    $s18 = "zU = true;}function nkP(cq){return Math.abs(cq);}if(0x56e2 <= parseInt(-40189)){var oq = 'turban';}var AJW = B(l);var sE = -1;if" ascii
    $s19 = "q = 0x23be;}var o1 = 1;if(Math.sin(o1) == 0){mSk = \"\\x66\\x38\\x62\\x31\\x38\\x35\\x39\";}else{var iPO = '32000';}var LB = -1;" ascii
    $s20 = "q) >= 0){var cj = \"\\x37\\x62\\x33\\x30\";}else{var yrx = false;}if(4935 >= parseInt(13258)){var eY = 47690;}var K2 = -1;if(Mat" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}