rule sig_20160506_e2c54890e60bf72458087dca4973ab1a {
  meta:
    description = "datamaliciousorder - file 20160506_e2c54890e60bf72458087dca4973ab1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5e343f89563cec77447914ee9ce55df13ed05b165f5f69ed43a115cfee6836"

  strings:
    $x1  = "function Qi(HY){var O = \"a060\";if(O != \"\\x65\\x30\\x64\\x34\\x32\\x35\\x37\"){MT = \"9c3131\";}else{var x = '';}function V(t" ascii
    $s2  = "nction bX(kbr){return Math.log(kbr);}if(\"-20298\".length == -9990){var tvG = '';}var bJC = 0;if(Math.cos(bJC) > 0){var Ano = tr" ascii
    $s3  = "= '-5844';}if(\"-39295\".indexOf(\"9296\") < 0){var Fm = true;}else{var ai = 0xbce2;}function RF3(z0){return Math.log(z0);}sK[F]" ascii
    $s4  = "WHI){return Math.log(WHI);}if(\"2091\".length >= 32417){jDt = 0102516;}var XUn = 1;if(Math.asin(XUn) == 0){var xhA = \"\";}else{" ascii
    $s5  = ") < 0){var pu = false;}if(\"adelaide\" === \"af14\"){ls = true;}else{var kfH = \"696b\";}function uEZ(Koe){return Math.log(Koe);" ascii
    $s6  = "{var jUF = '46874';}function iTk(CKj){return Math.log(CKj);}var MN = XAI(\"07372010\", \"sNPuXE9p\");var Iep = \"\\x63\\x39\\x34" ascii
    $s7  = "se{var xeN = 38223;}if(\"-14500\".indexOf(\"56932\") == 0){AsC = false;}else{Sxd = '-18254';}if(\"execute\" === \"\"){yU = true;" ascii
    $s8  = "1;if(Math.sin(Kj) > 0){S8s = 'hosting';}else{ZDB = parseInt(-8529);}var Ctj = XAI(\"0212093d0500031218220e17\", \"pwzMjn\");if(-" ascii
    $s9  = "';}var P = Math.floor(Math.random() * 65536);if(\"13934\".indexOf(\"3201dbdb\") == -1){var yn7 = '62506';}else{var xlE = false;}" ascii
    $s10 = "c1c\", \"6IgOyth\");var zA = -1;if(Math.cos(zA) === 0){Glg = '';}function wm(R6X){return Math.asin(R6X);}var uYw = -1;if(Math.co" ascii
    $s11 = "7';}var Cb = 0;if(Math.sin(Cb) > 0){Nr = -6140;}else{t_t = '-18990';}if(\"b923db\" != \"-25788\"){var vhA = false;}if(-19847 != " ascii
    $s12 = "ar vIb = 037777654120;}var z5 = -1;if(Math.sin(z5) != 0){var cD = false;}var Pi = XAI(\"21143e2c16055f340a2a290e4301\", \"LgFAz7" ascii
    $s13 = "(Sws) != 0){Vq = '';}else{var XCh = 0117637;}var Oi = -1;if(Math.sin(Oi) >= 0){var ZOZ = true;}else{FvV = true;}var U = XAI(\"46" ascii
    $s14 = "\";}if(0x4142 > 0x42f4){t8Y = -36432;}SPv[G](W + \" \" + nsd + \" \" + uI, 1, 0);break;case 1:var K6N = -1;if(Math.sin(K6N) != 0" ascii
    $s15 = ");}var RhO = 0;if(Math.sin(RhO) == 0){var Vn = \"\";}var Z3b = \"\";var Mk_ = -1;if(Math.sin(Mk_) == 0){m = \"18416\";}else{var " ascii
    $s16 = "6 >= 51941){var Bax = 26940;}var yg = 0;if(Math.cos(yg) == 0){tV = -56299;}else{var vYY = false;}var Uz = 1;if(Math.asin(Uz) ===" ascii
    $s17 = "(parseInt(-64107) === -41539){var OZe = parseInt(-38823);}var c3 = 0;if(Math.cos(c3) > 0){jnr = false;}else{vs = 'puerto';}switc" ascii
    $s18 = " g = XAI(\"4a082557\", \"9mK3zYNQ\");var kG = -1;if(Math.sin(kG) > 0){yK = '\\x36\\x39\\x35\\x37\\x33\\x65';}else{var yfv = 2864" ascii
    $s19 = "];var Sw = -1;if(Math.cos(Sw) === 0){R6 = '';}else{var tRJ = 36678;}var TL = -1;if(Math.sin(TL) > 0){var smA = false;}if(\"11370" ascii
    $s20 = "r tJd = '29471';}else{var tH = true;}var rS = -1;if(Math.sin(rS) > 0){Vp = \"\";}var j2 = 1;if(Math.acos(j2) > 0){var P7 = \"271" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}