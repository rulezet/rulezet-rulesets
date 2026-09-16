rule sig_20160505_305635496ed87d773fa21f55c4c6b96d {
  meta:
    description = "datamaliciousorder - file 20160505_305635496ed87d773fa21f55c4c6b96d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb6b2d215d30dc9ec51fb16085c48e43843ec7f87d68551dd67e2de179d5f120"

  strings:
    $x1  = "function BIR(Vss, rM){var UFh = \"hittite\";if(UFh == \"31417\"){qr = false;}else{Iy = 0xef41;}var UL = -1;if(Math.sin(UL) >= 0)" ascii
    $s2  = "(\"40115\".length != 037777676115){IP = '1e2d681';}function kb(SAa){return Math.log(SAa);}var YJ = \"44606\";var VN = \"43e84a\"" ascii
    $s3  = "Math.asin(Qn) === 0){sI7 = true;}else{var J = \"flout\";}var EI = BIR(k, rM);if(\"vegetarian\".length > -16950){var un = \"\";}v" ascii
    $s4  = "111011100, 2);}var wgV = \"\";if(wgV == \"45fe\"){var BP8 = '3781';}else{var jw = true;}function ew(Wi){return Math.log(Wi);}var" ascii
    $s5  = " Math.log(DYX);}if(R3v[H] == 1){var m6e = 1;if(Math.cos(m6e) != 0){var v9k = \"4362\";}else{var yyz = parseInt(-57578);}var d7z " ascii
    $s6  = "(RSD){return Math.log(RSD);}var MF = B[3];if(\"-30524\".lastIndexOf(\"7489030\") > 0){wA = '-18124';}else{var AR = parseInt(1001" ascii
    $s7  = "return Math.exp(NlC);}var G = yBm(\"0f0915\", \"key\");}else{var QQ = -1;if(Math.cos(QQ) == 0){vmz = parseInt(37777701621, 8);}e" ascii
    $s8  = "stIndexOf(\"\\x62\\x34\\x31\\x63\\x65\\x62\") == -1){var rv = \"elevate\";}else{eo = \"\";}var Vj = \"\\x66\\x64\\x61\\x63\\x36" ascii
    $s9  = "rue;}if(\"\\x66\\x39\\x34\\x38\\x30\".lastIndexOf(\"\") != -1){XOR = true;}var aL = 1;if(Math.acos(aL) > 0){var T = \"\";}S = S " ascii
    $s10 = "rn Math.cos(lx);}if(\"pond\".lastIndexOf(\"68e44\") == -1){rd = \"6b42c916\";}else{var LtZ = '';}if(parseInt(10065, 8) === 01320" ascii
    $s11 = "2aa15bd';}var Ap = yBm(\"04151c05\", \"key\");if(\"f39bb0a\".indexOf(\"-10940\") == -1){var ed7 = false;}else{ZVa = true;}var Og" ascii
    $s12 = "l = 1;if(Math.acos(dl) == 0){var _0 = false;}var Eyz = 1;if(Math.cos(Eyz) >= 0){var DW = 2144;}else{ee = -21194;}for(var sDC = 0" ascii
    $s13 = "'keyboards';}if(\"-41074\".lastIndexOf(\"\\x65\\x38\\x33\\x66\\x61\\x38\\x66\\x33\") == 0){wYe = true;}var F6O = -1;if(Math.asin" ascii
    $s14 = "Int(35034);}var h4 = -1;if(Math.sin(h4) > 0){var ec = '';}else{JI = 'axiom';}if(-8774 != parseInt(111111111111111101001101100111" ascii
    $s15 = "\"){var MvI = -13713;}var Yr = 0;if(Math.sin(Yr) != 0){var o0 = false;}else{ta = false;}var Sw = -1;if(Math.acos(Sw) === 0){R6 =" ascii
    $s16 = "if(BaY === op){deL = false;}else{yh = '-22973';}var SBr = -1;if(Math.cos(SBr) == 0){var pP = \"4b4488\";}S = 0;}}if(\"e0a0a\".in" ascii
    $s17 = "var ZmS = 0;if(Math.sin(ZmS) > 0){lrN = false;}else{aNq = 'd91eef84';}var Vm = -1;if(Math.sin(Vm) != 0){var pc = '-10755';}else{" ascii
    $s18 = "cC = \"-33518\";if(Vj === XcC){cDV = -29790;}else{ed = \"\";}KQ[Tq]();if(parseInt(23446) >= 0xdc5c){KXP = \"61626\";}if(\"alumin" ascii
    $s19 = "\"-62778\";var AE7 = \"\";if(CL === AE7){var h40 = true;}else{var YlV = 'likelihood';}var mvT = -1;if(Math.sin(mvT) === 0){qzr =" ascii
    $s20 = "9K = 0;if(Math.cos(H9K) === 0){fXI = false;}else{Lg = '-11334';}if(\"-55910\".lastIndexOf(\"\\x65\\x34\\x31\\x36\\x30\\x35\") ==" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}