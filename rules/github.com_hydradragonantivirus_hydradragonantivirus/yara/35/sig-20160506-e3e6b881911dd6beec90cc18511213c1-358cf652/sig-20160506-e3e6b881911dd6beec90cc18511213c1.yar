rule sig_20160506_e3e6b881911dd6beec90cc18511213c1 {
  meta:
    description = "datamaliciousorder - file 20160506_e3e6b881911dd6beec90cc18511213c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b91f908fe210d2523d8919904ee88ff5e14ddee8a24d1f5c4ee5594bb0aa819"

  strings:
    $s1  = "function Jc(sY5){if(\"a01f3ca6\".indexOf(\"\\x36\\x31\\x64\\x65\\x65\\x65\") < 0){var c = true;}else{var iG = parseInt(113233, 8" ascii
    $s2  = "return Math.log(l1);}var xzf = -1;if(Math.cos(xzf) == 0){var oA = '63261';}var it9 = 1;if(Math.cos(it9) >= 0){Lj = '8223e782';}i" ascii
    $s3  = " -1;if(Math.acos(tf) != 0){var sub = false;}else{var Ag = 63971;}if(parseInt(38061) != 38553){var Ppg = \"meyer\";}else{var zj =" ascii
    $s4  = "16){Gw = \"darkness\";}if(\"\".length === -21352){Oi0 = \"19778\";}var H = Bh[aU](2);if(\"pe\" == \"45303\"){qQ = false;}else{HW" ascii
    $s5  = "Mg){return Math.cos(Mg);}if(\"\".indexOf(\"51641\") < 0){t3C = 0x72b5;}else{var iBq = -13102;}var od = 0;if(Math.asin(od) != 0){" ascii
    $s6  = "7';}if(\"\".indexOf(\"-43009\") == -1){V7p = parseInt(-51353);}var bop = 0;if(Math.sin(bop) === 0){Jht = true;}var s = gDg(\"372" ascii
    $s7  = "r bIW = -1;if(Math.asin(bIW) != 0){var RyB = false;}var ZP = gDg(\"153d01\", \"qQmufR\");}else{function qzP(_dg){return Math.sin" ascii
    $s8  = "th.cos(BV) > 0){var Yzt = \"won\";}else{I6V = '';}if(\"-24772\".indexOf(\"-41115\") != -1){dL = '';}else{var OLB = parseInt(5503" ascii
    $s9  = "function I(V){return Math.abs(V);}var J = -1;if(Math.asin(J) != 0){Ud = parseInt(21367, 8);}var s0N = 1;if(Math.cos(s0N) >= 0){r" ascii
    $s10 = "k = -1933;}else{var w6 = true;}var BVk = 0;if(Math.cos(BVk) != 0){var Cg6 = \"22616\";}else{var sl = 3728;}function htW(HeY){ret" ascii
    $s11 = "daniel\";if(FZ == Tbf){fjb = '-8559';}var o = -1;if(Math.sin(o) >= 0){var jR = '';}else{jtb = '7d4a';}var _TK = -1;if(Math.sin(_" ascii
    $s12 = "= 0;if(Math.cos(VCI) === 0){var eL = 'administered';}else{var EQa = \"army\";}if(\"7001\".lastIndexOf(\"55175\") == -1){var _uC " ascii
    $s13 = "b14\", \"usqnfCH\");}var FrV = 1;if(Math.sin(FrV) > 0){var yS = \"dike\";}var rAp = -1;if(Math.asin(rAp) >= 0){zZL = 014625;}els" ascii
    $s14 = "se{var HyN = \"\";}var jfA = 0;if(Math.sin(jfA) > 0){te = 'develops';}return(uqg);}function gDg(vE, LCn){var dOd = -1;if(Math.co" ascii
    $s15 = "ctiveXObject(p);if(\"compulsory\" == \"d37a5f2\"){fUd = 'suddenly';}else{Xo6 = true;}if(\"\".lastIndexOf(\"\") == -1){var TM = 0" ascii
    $s16 = "(dr){return Math.sqrt(dr);}var XwY = -1;if(Math.sin(XwY) === 0){Qh7 = 'c5c6';}if(\"\".length == parseInt(130157, 8)){var NYh = 0" ascii
    $s17 = "lJ != QK){vA = -56906;}var VKJ = 1;if(Math.sin(VKJ) > 0){SGz = '';}else{yb = \"observatory\";}function g_y(Ej){return Math.asin(" ascii
    $s18 = ");}var aU = gDg(\"282f2c1c023405082e263e001e350313\", \"OJXorQfa\");function vW(Es){return Math.ceil(Es);}if(\"a386c7\".length =" ascii
    $s19 = "xOf(\"always\") == -1){var FB = '\\x61\\x31\\x38\\x31\\x32\\x38';}Ku1 = 0;}}var Uc = -1;if(Math.asin(Uc) >= 0){eZZ = false;}func" ascii
    $s20 = "i = \"\";}else{ne = 16207;}var Zbz = 0;if(Math.asin(Zbz) != 0){GPd = true;}var dm = Iby[3];if(\"-7237\".length == -27753){rB = '" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}