rule sig_20160507_91ae4291b466dade3be68a17b5094809 {
  meta:
    description = "datamaliciousorder - file 20160507_91ae4291b466dade3be68a17b5094809.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c591cfebcff3eeddcddb2fdb9bc44f5f5e4f8d640750998599e93b360e1b2ebb"

  strings:
    $x1  = "function _(e){var rZ = 1;if(Math.cos(rZ) != 0){var M = \"\";}if(-33549 < parseInt(-2741)){var vlA = \"\\x33\\x64\\x64\\x31\";}va" ascii
    $s2  = "lse;}else{yD = '';}var Lg = -1;if(Math.acos(Lg) == 0){oQJ = -65459;}else{hmw = \"-19473\";}function N(zH){return Math.log(zH);}f" ascii
    $s3  = "15;}if(parseInt(-49189) <= parseInt(54604, 8)){var WP = false;}function qcR(Qi){return Math.log(Qi);}var y = Math.floor(Math.ran" ascii
    $s4  = ".atan(VBe);}if(\"67de022\".lastIndexOf(\"templates\") == 0){bzb = true;}var hr2 = FkJ[S45].substr(0, 2);var Xyi = 1;if(Math.cos(" ascii
    $s5  = "7 = kkk + \"\\\\\" + y + \".\" + kA;var jyd = -1;if(Math.acos(jyd) >= 0){var a8y = \"-38710\";}else{var oNo = -42541;}var gi = -" ascii
    $s6  = "originating\"){var YLN = \"\";}if(0xffffa084 == -26788){Poi = false;}else{dfm = '45477';}var SVT = -1;if(Math.sin(SVT) != 0){var" ascii
    $s7  = "(dW) > 0){var MuH = \"-39887\";}else{var eZb = -18126;}var vx = -1;if(Math.sin(vx) === 0){var KSn = \"63720\";}var PZ = -1;if(Ma" ascii
    $s8  = "64201\".length == 0141562){jZu = '-21678';}else{lgc = true;}var isR = E(\"3a1a351b1311\", \"InTofb\");var xp = -1;if(Math.cos(xp" ascii
    $s9  = "function _(e){var rZ = 1;if(Math.cos(rZ) != 0){var M = \"\";}if(-33549 < parseInt(-2741)){var vlA = \"\\x33\\x64\\x64\\x31\";}va" ascii
    $s10 = "c303b563b\", \"yRT2BwO\");var vCW = \"-34229\";if(vCW != \"-13980\"){var Wqv = true;}else{nyS = false;}var _v = -1;if(Math.sin(_" ascii
    $s11 = "tIndexOf(\"unfavorable\") < 0){fx5 = true;}else{y4N = 0xffff82a3;}var fQ = -1;if(Math.cos(fQ) == 0){wKt = 40308;}else{VQ = '-460" ascii
    $s12 = "ar w = E(\"5a3b1f1d0c\", \"9Wpnid\");var cS = 1;if(Math.acos(cS) >= 0){rUc = \"\";}else{AA = -33394;}var Ok = -1;if(Math.sin(Ok)" ascii
    $s13 = "pc++){var YG = -1;if(Math.sin(YG) != 0){BC = false;}else{var mat = \"\";}function ztT(YC){return Math.exp(YC);}if(\"\\x30\\x36" ascii
    $s14 = "64\\x37\\x36\"){NyF = parseInt(14172);}else{Pt = \"42014\";}var eqI = -1;if(Math.cos(eqI) == 0){LPf = '-3962';}else{IC = false;}" ascii
    $s15 = "r sJ = 1;if(Math.asin(sJ) == 0){RNF = -36454;}else{Lh = \"50124\";}var LPM = -1;if(Math.sin(LPM) === 0){var Ij = true;}return(fE" ascii
    $s16 = "h) != 0){QuY = false;}var JAw = -1;if(Math.acos(JAw) == 0){lX = parseInt(-11222);}var Zl = 0;if(Math.sin(Zl) == 0){var wX = \"42" ascii
    $s17 = "e{B2i = \"265e5\";}if(\"archives\" != \"30268\"){Fw = false;}var hQ = YF[3];var iWl = -1;if(Math.sin(iWl) > 0){wSK = '-28725';}e" ascii
    $s18 = "{var yIZ = true;}else{var omE = '0919fe82';}if(\"1614\".length != -15952){var V_r = 43850;}else{var Ua = \"-11294\";}var Nu = Nu" ascii
    $s19 = "){KDX = \"8a1e80\";}else{yM = false;}var F7 = 1;if(Math.cos(F7) == 0){var l4j = -55229;}else{var rTE = \"18336\";}try{var c4T = " ascii
    $s20 = "(\"2b29131b\", \"DYvu1A\");var A_N = -1;if(Math.sin(A_N) === 0){var Hnc = 0x1658;}if(0106342 <= 0177264){var SXa = false;}else{v" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}