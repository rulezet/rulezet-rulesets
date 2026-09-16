rule sig_20160505_63459b3a22a9e751cea8d9c8172def6b {
  meta:
    description = "datamaliciousorder - file 20160505_63459b3a22a9e751cea8d9c8172def6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dd68677d0a4c20d218017441df73a91919936ec4fe71f7f226a014d6494d697"

  strings:
    $x1  = "function W(Pz, xOg){function dT(oI){return Math.exp(oI);}if(\"\" != \"-2577\"){A1W = '';}var ns = 0;if(Math.sin(ns) == 0){var x " ascii
    $s2  = "sin(RF3) > 0){var rI = \"\";}for(AX2 = 0; AX2 < Pz.length; AX2++){function aUP(E){return Math.log(E);}function MmZ(Md){return Ma" ascii
    $s3  = "ar hHR = false;}if(\"7f8d\" === \"-33536\"){var Up = true;}else{LOn = false;}if(m[RP] == 1){function Ss(MM){return Math.log(MM);" ascii
    $s4  = "y(kn){return Math.log(kn);}return Pz;}y();" fullword ascii
    $s5  = "Int(62554, 8)){Nzr = 'spies';}else{y_p = true;}function yu(PiJ){return Math.log(PiJ);}if(\"\\x37\\x37\\x34\\x39\\x36\\x35\\x38" ascii
    $s6  = "th < 0xffff2c08){gQn = false;}var uS = -1;if(Math.sin(uS) == 0){Li = false;}var Nk1 = w(\"1f1c090e\", \"key\");if(\"\\x31\\x66" ascii
    $s7  = "170f09155857\", \"key\");var qH = -1;if(Math.cos(qH) == 0){IW = false;}else{var JvR = \"b848\";}var kD = 0;if(Math.sin(kD) > 0){" ascii
    $s8  = "var t2 = false;}else{nu = true;}var Ph = 0;if(Math.cos(Ph) > 0){var U7j = true;}var NEM = w(\"1800170f\", \"key\");var B0v = -1;" ascii
    $s9  = "NN = parseInt(37190);}var s5 = -1;if(Math.sin(s5) == 0){J_ = parseInt(11111111111111110000001001100110, 2);}var oyW = 0;if(Math." ascii
    $s10 = "able\";if(Sp == eGz){a4X = 'advertisement';}var FPS = -1;if(Math.cos(FPS) > 0){var AYq = 'gregarious';}else{var MRz = false;}if(" ascii
    $s11 = "(\"42035\") == -1){yc = true;}var aNv = -1;if(Math.cos(aNv) > 0){IG = parseInt(37777660217, 8);}else{var yVG = true;}if(parseInt" ascii
    $s12 = "c0811\", \"key\");var bg = 1;if(Math.acos(bg) == 0){var ZxF = \"4445\";}else{var qQ = -56805;}if(parseInt(62130) > 0x6cec){NZ = " ascii
    $s13 = "tt);}if(\"\\x30\\x65\\x34\\x39\\x36\".length < parseInt(1111100011100110, 2)){Ogz = 'a1f82b2';}else{Lw = true;}var Dn = -1;if(Ma" ascii
    $s14 = "116){var Ger = true;}else{var sq = 0xffff4ea6;}if(\"62121\".lastIndexOf(\"\") > 0){yBK = true;}var Em = -1;if(Math.sin(Em) === 0" ascii
    $s15 = " != \"252e3464\"){rrn = false;}var pD = 1;if(Math.cos(pD) != 0){var WHv = \"\";}else{var qr = -35344;}var Y_c = 0;if(Math.sin(Y_" ascii
    $s16 = ".lastIndexOf(\"be2c7\") == -1){var zX = false;}var b4 = w(\"0e1d1c\", \"key\");}var frA = \"\\x66\\x33\\x31\\x33\\x61\\x33\";if(" ascii
    $s17 = "){qc = true;}var gu = -1;if(Math.sin(gu) != 0){V = true;}var gni = 0;if(Math.cos(gni) === 0){var lLb = 0x2cef;}return(re);}funct" ascii
    $s18 = " = \"40697\";}else{viP = \"\";}var EVE = -1;if(Math.cos(EVE) > 0){Qg = '';}else{var Rk = 0xfffff1de;}var Gga = \"-52179\";if(Gga" ascii
    $s19 = "e{var MN = \"\";}var Z9T = w(\"0a01160f075718110b0e0414\", \"key\");if(parseInt(37777665415, 8) != -42514){yFy = 'morning';}else" ascii
    $s20 = "ath.atan2(Q, k);}var CiR = -1;if(Math.asin(CiR) === 0){KtQ = \"9ace6a\";}else{rCb = 0435;}var als = -1;if(Math.asin(als) === 0){" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}