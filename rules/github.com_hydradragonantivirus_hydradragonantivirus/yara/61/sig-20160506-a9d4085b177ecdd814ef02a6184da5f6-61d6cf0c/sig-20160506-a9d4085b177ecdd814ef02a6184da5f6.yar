rule sig_20160506_a9d4085b177ecdd814ef02a6184da5f6 {
  meta:
    description = "datamaliciousorder - file 20160506_a9d4085b177ecdd814ef02a6184da5f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89a9bc20a23c919dd7a747bb612cd6e812aadecf892e15dfa649b4a1fbfe31dd"

  strings:
    $x1  = "function o(Ak, z){var N = \"48963\";if(N === \"\"){mrS = 060431;}else{Nx = \"\\x64\\x65\\x37\\x35\";}try{var QD = \"50396\";}cat" ascii
    $s2  = "if(\"-51021\".length != 63791){var HP = \"28264\";}function fTQ(x6q){return Math.log(x6q);}if(\"-33876\".indexOf(\"222ac7\") != " ascii
    $s3  = "(eJ);}function WX(vTh){return Math.log(vTh);}if(\"\".length == 53830){var DW = \"\";}else{var UB = false;}function ie7(n5T){retu" ascii
    $s4  = "c55\", \"YnL0Il\");if(\"\".indexOf(\"commonwealth\") == -1){xD = true;}else{yp = parseInt(-23942);}var o_6 = 1;if(Math.cos(o_6) " ascii
    $s5  = "070;}var _r = -1;if(Math.sin(_r) == 0){BK = parseInt(17302);}else{var oI = true;}var g = kHn(\"533f02111c2e17115536100d002f110a" ascii
    $s6  = "59520\";}if(\"48892\".length >= -15393){var Fx = true;}else{Pe = false;}EFj = EFj + 1;function XtQ(wv1){return Math.acos(wv1);}v" ascii
    $s7  = "L = \"aristocrat\";if(pL == \"\"){var BCq = 'a3e03';}else{jVH = '30159';}V[rM]();function BY(T3V){return Math.cos(T3V);}if(\"\"." ascii
    $s8  = "Aq1 = false;}else{var oE = '-8423';}var zQe = -1;if(Math.asin(zQe) > 0){VUR = false;}iT[H](XcD + \" \" + Vss + \" \" + kA, 1, 0)" ascii
    $s9  = "f(\"computed\".lastIndexOf(\"impaled\") == -1){var cj = \"-38438\";}if(\"0478acff\".indexOf(\"19519\") < 0){var D1 = 34560;}else" ascii
    $s10 = " 0;if(Math.asin(ZP) == 0){var l54 = false;}var OmM = -1;if(Math.cos(OmM) > 0){Lch = \"-30355\";}else{GP = 0xffff2dce;}if(\"\".le" ascii
    $s11 = "== \"6836\"){var WjY = \"-38878\";}var Wb = -1;if(Math.cos(Wb) >= 0){var tmJ = \"\";}else{var wE = parseInt(51310, 8);}var AEf =" ascii
    $s12 = "}else{var qW = 0xffff6f76;}var TF = Oxf();var bX = -1;if(Math.sin(bX) == 0){yBr = false;}if(\"-35998\".lastIndexOf(\"47597\") ==" ascii
    $s13 = "= -9730;}function ks(Wq){return Math.tan(Wq);}iT[H](Vss, 1, 0);break;}var scT = \"\\x33\\x30\\x30\\x32\\x65\";if(scT == \"-34632" ascii
    $s14 = "5\\x39\\x39\\x65\\x36\\x38';}var mp = 0;if(Math.cos(mp) != 0){var L8 = '-56491';}else{Gfl = '';}var tld = -1;if(Math.asin(tld) >" ascii
    $s15 = "Math.asin(AEf) == 0){var tJ = 037777677506;}else{nrs = parseInt(5625, 8);}var v = kHn(\"16395220073a\", \"eM3TrI2S\");var eok = " ascii
    $s16 = "1;if(Math.sin(GRV) >= 0){qSe = -53967;}if(\"\\x30\\x34\\x36\\x31\\x32\".length < -2288){var eep = true;}for(hSs = 0; hSs < EPC.l" ascii
    $s17 = "exOf(\"\\x31\\x33\\x32\\x64\\x64\\x61\") != -1){Oen = \"-46543\";}else{m_e = 0x7a39;}var dQ = 1;if(Math.cos(dQ) != 0){var he = 0" ascii
    $s18 = "}var Igu = -1;if(Math.asin(Igu) === 0){KT = '\\x62\\x35\\x37\\x34\\x32';}var hBU = 0;if(Math.sin(hBU) > 0){ZaI = '18248';}else{g" ascii
    $s19 = "r sDC = kHn(\"3c183515450d29102f15\", \"OyCp1b\");if(\"airports\".lastIndexOf(\"7151\") == -1){var wd = 'cod';}else{var Gn = \"6" ascii
    $s20 = "\";}else{var xJ = false;}var ssh = 0;if(Math.cos(ssh) === 0){var WPK = \"\\x66\\x65\\x31\\x33\\x31\\x64\\x37\";}else{var ft = -3" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}