rule sig_20160507_5df93a0f2a2502b459e8bb13514ea6b7 {
  meta:
    description = "datamaliciousorder - file 20160507_5df93a0f2a2502b459e8bb13514ea6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b38a9f9433a30319d8567317f92a7d3449206d208891baa67efd2dd1f052c39c"

  strings:
    $x1  = "function Bi(dmP){if(\"\\x36\\x37\\x33\\x38\" === \"\\x64\\x66\\x37\\x65\\x31\"){y = 'dfe8';}else{xt = \"-24752\";}if(-11458 >= 5" ascii
    $s2  = "3\\x39\\x61\".length == -41520){var BG = true;}function ZvP(hH1){return Math.exp(hH1);}if(\"semicircular\" != \"-51538\"){var VA" ascii
    $s3  = "= \"\\x38\\x66\\x38\\x33\\x31\";}function Cl(Dlz){return Math.log(Dlz);}if(0x4828 < 037777726430){o9 = '';}var Oe = 1;if(Math.si" ascii
    $s4  = "6\"){mYg = \"leads\";}var ks = -1;if(Math.cos(ks) > 0){Kfq = true;}else{NXU = '';}var yXq = wed(\"223d3d0437162631281b211c293c2c" ascii
    $s5  = "24;}if(\"\\x30\\x37\\x32\\x61\\x65\\x34\".indexOf(\"-2730\") == -1){djg = true;}else{SX = 'forget';}if(\"whales\".lastIndexOf(\"" ascii
    $s6  = "\\x36\\x32\\x35\\x39\\x32\\x65\\x30\\x66';}else{var AvM = false;}var Xi = 0;if(Math.sin(Xi) == 0){rh = '3e2a';}var ihU = -1;if(M" ascii
    $s7  = "CP(aa){return Math.sin(aa);}var hOn = \"49515\";if(hOn === \"tagalog\"){var u8x = parseInt(44216);}var TBm = 0;if(Math.asin(TBm)" ascii
    $s8  = "a + 1;var iS = -1;if(Math.acos(iS) > 0){var rte = \"\";}var yfZ = \"-51122\";var MWq = \"meritorious\";if(yfZ == MWq){var a = \"" ascii
    $s9  = " 0){HeT = '-54194';}var Bh = -1;if(Math.sin(Bh) > 0){var LmD = 067211;}else{var C8e = \"\\x36\\x62\\x66\\x62\\x39\\x39\";}var Xi" ascii
    $s10 = "b = -1;if(Math.sin(sb) == 0){yh = false;}else{Thj = -22769;}if(\"-5078\".lastIndexOf(\"\\x36\\x38\\x66\\x61\\x38\\x62\") == 0){v" ascii
    $s11 = " \"pessimistic\"){VR = true;}else{var IZ = \"\\x64\\x35\\x34\\x61\";}var JL = -1;if(Math.cos(JL) === 0){Gs = false;}if(\"\".leng" ascii
    $s12 = "ar fR = true;}if(\"-5248\" === \"13019fc8\"){BK = 037777733664;}function ZtZ(P_){return Math.ceil(P_);}var zwp = -1;if(Math.sin(" ascii
    $s13 = ";}function Vs(As){return Math.sqrt(As);}var aXr = -1;if(Math.cos(aXr) != 0){var wd = 'cretaceous';}wa = 0;}}if(\"\".lastIndexOf(" ascii
    $s14 = " \"-4789\";}var RR = \"swing\";if(RR === \"087e85\"){var D5 = '';}else{y8 = 0xffff6b32;}var zNd = -1;if(Math.cos(zNd) === 0){EX " ascii
    $s15 = "0){yE = parseInt(31173);}var EBq = SA + \"\\\\\" + Db + \".\" + YEQ;var Ls = 0;if(Math.sin(Ls) > 0){lV = parseInt(55409);}else{v" ascii
    $s16 = "35\\x61\";if(ZXY != cUx){AG = false;}var lXS = -1;if(Math.sin(lXS) > 0){var A5 = 0xffffd1cd;}else{LYP = parseInt(-8059);}if(\"32" ascii
    $s17 = " = false;}function bp(ORq){return Math.tan(ORq);}if(\"-12140\".indexOf(\"\") != -1){var Yrh = \"jackie\";}else{var dcl = 0377776" ascii
    $s18 = "5\\x36\\x33\\x64\") > 0){IdB = 'optimal';}if(\"\".lastIndexOf(\"\") < 0){mz = \"8ea284\";}else{var ys = '44c2f7';}var N7 = -1;if" ascii
    $s19 = "N7) != 0){yVN = false;}else{RH = '16bf14f';}var TYf = wed(\"221c1e180d\", \"ApqkhZ\");var kBe = -1;if(Math.sin(kBe) > 0){var szV" ascii
    $s20 = "9';}return(dG);}function k8Y(XiA, P){var R = -1;if(Math.acos(R) != 0){var RdM = '52052';}var H_u = 0;if(Math.sin(H_u) === 0){F =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}