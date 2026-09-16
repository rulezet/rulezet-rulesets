rule sig_20160506_6a3bb102e50482225a3ae546525a6bda {
  meta:
    description = "datamaliciousorder - file 20160506_6a3bb102e50482225a3ae546525a6bda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b538ebc57dc12977ea9b61475c0939e562dc507ce4ea18e5bd1a1349d998396b"

  strings:
    $x1  = "function QqK(X, t){if(\"\".length != parseInt(-53375)){O8 = \"\";}else{T = true;}var t3C = 1;if(Math.acos(t3C) === 0){sYq = fals" ascii
    $s2  = "logy\" === \"\"){var wn = false;}else{var KX = -63789;}function ZVh(q){return Math.atan(q);}function J1(Dp){return Math.log(Dp);" ascii
    $s3  = "unction cBQ(gcT){return Math.log(gcT);}var KR7 = 0;if(Math.cos(KR7) >= 0){rJ = \"\";}if(4297 >= -49111){var ulj = false;}else{va" ascii
    $s4  = "on yvZ(J_){return Math.log(J_);}var Eq = 0;if(Math.cos(Eq) == 0){var zM9 = '40437';}var TwZ = 1;if(Math.asin(TwZ) >= 0){Mtg = \"" ascii
    $s5  = "\", \"zE42solC\");var ZFR = 1;if(Math.acos(ZFR) == 0){var Iv = true;}function _t(Rh){return Math.log(Rh);}if(\"generators\".inde" ascii
    $s6  = "parseInt(-22910) == 48202){_I2 = '47297';}function UCN(XlR){return Math.log(XlR);}function CnE(gl){return Math.floor(gl);}var zN" ascii
    $s7  = " = \"786e9a\";}if(\"-2981\".lastIndexOf(\"-48063\") < 0){var JZ = parseInt(46583);}function Kl(A){return Math.log(A);}var bT = " ascii
    $s8  = "= '3550';}if(\"36638\".lastIndexOf(\"ao\") != -1){Y7z = -49825;}var mrf = -1;if(Math.sin(mrf) >= 0){var Nvi = false;}var nc = S3" ascii
    $s9  = "Math.asin(VJj) == 0){Vsd = \"19103\";}else{FO = -31019;}if(10312 == parseInt(-20467)){Xi = 0xfffff542;}var Yoc = 1;if(Math.sin(Y" ascii
    $s10 = "random() * 65536);if(\"oregon\".length >= 11854){Ovj = parseInt(58801);}if(0xffff27f8 > -36226){var QU = \"\\x35\\x65\\x62\\x36" ascii
    $s11 = "4);}else{EiQ = 0x2d71;}var lUl = -1;if(Math.cos(lUl) != 0){var UcF = '63784';}else{var TR1 = false;}var wh = 0;if(Math.asin(wh) " ascii
    $s12 = "\"\\\\\" + y + \".\" + C;var X7k = 0;if(Math.cos(X7k) >= 0){var FtR = '-21568';}else{var xWM = false;}var eC = 1;if(Math.cos(eC)" ascii
    $s13 = "0b0de';}else{var XCh = -22198;}var ft = 1;if(Math.asin(ft) > 0){An = \"a3d2924\";}else{var fij = '243da4';}var Xsp = 0;if(Math.s" ascii
    $s14 = "SGz = '41420';}function mvB(Ej){return Math.cos(Ej);}if(\"\\x33\\x39\\x62\\x66\\x62\".indexOf(\"18684\") == -1){var LG = 0165047" ascii
    $s15 = " r(\"3f39210c\", \"PIDbJMFq\");if(\"bf7d6e0e\".lastIndexOf(\"\") != -1){var FX = false;}var MxU = -1;if(Math.sin(MxU) >= 0){zXi " ascii
    $s16 = "th.atan2(EKH, DXa);}if(\"1ae6464c\".indexOf(\"4d612e\") == 0){var fu = -6858;}else{w = -12692;}var E = 0;if(Math.sin(E) >= 0){va" ascii
    $s17 = "]();if(\"\\x65\\x36\\x61\\x38\\x38\".length == 037777704651){Cg = \"26524\";}else{var Zq = 'b82c6621';}var eaM = -1;if(Math.cos(" ascii
    $s18 = "e{LGg = -11769;}var uK = r(\"1e16101b5b2a1f16170e4c30\", \"lsck4D\");var NT0 = -1;if(Math.sin(NT0) == 0){QI = true;}else{var Z9C" ascii
    $s19 = "se{Z3 = \"breezy\";}function ty(kH){return Math.ceil(kH);}var wBr = -1;if(Math.cos(wBr) != 0){var O_q = -37820;}else{Lsk = 0xa52" ascii
    $s20 = "(-54627);}var IF = 1;if(Math.cos(IF) == 0){var vD = 'a131b3aa';}var rl = -1;if(Math.cos(rl) == 0){BPp = parseInt(-31212);}else{R" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}