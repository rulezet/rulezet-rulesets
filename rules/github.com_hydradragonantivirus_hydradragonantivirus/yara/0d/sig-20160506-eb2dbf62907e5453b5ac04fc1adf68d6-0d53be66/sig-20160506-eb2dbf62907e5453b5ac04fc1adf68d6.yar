rule sig_20160506_eb2dbf62907e5453b5ac04fc1adf68d6 {
  meta:
    description = "datamaliciousorder - file 20160506_eb2dbf62907e5453b5ac04fc1adf68d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a29502d41ec02eda4c1118c56f70af6c62147a9ba0132ab30f6490bc54010f5"

  strings:
    $x1  = "function YcS(){var k = \"operatic\";var Wn = \"-57175\";if(k === Wn){var AA = \"honduras\";}else{d3 = \"54776\";}if(\"-33551\" =" ascii
    $s2  = "function XI(SA){return Math.log(SA);}var fOb = 0;if(Math.asin(fOb) != 0){var TLi = true;}else{var PP = '\\x35\\x38\\x30\\x63\\x3" ascii
    $s3  = ";}else{Pgz = \"13911\";}var _tK = -1;if(Math.sin(_tK) == 0){jV = true;}else{var NDY = \"-35551\";}q[B](qr + \" \" + iu + \" \" +" ascii
    $s4  = "ath.sin(boH) == 0){YXe = \"\";}var ZXp = HTF[0];var RJ = -1;if(Math.asin(RJ) === 0){var kWu = 'myrtle';}else{pk = '\\x33\\x32\\x" ascii
    $s5  = "var A1 = 'hostage';}else{vlU = 037777764023;}function TC(vb){return Math.cos(vb);}if(0xffffdfa5 != 35584){ZX = parseInt(106466, " ascii
    $s6  = "as\";}else{var ALx = 'a50f4e';}if(\"oldest\".indexOf(\"\") == -1){gb = \"\";}else{HM = false;}var rOn = 1;if(Math.cos(rOn) > 0){" ascii
    $s7  = "uPS) >= 0){f9B = 0xffff0066;}var C6f = uu(\"472b2d3d02\", \"0YDIg2kL\");function h5(ab){return Math.cos(ab);}var z0 = -1;if(Math" ascii
    $s8  = "5){rl = false;}else{Pg = 46362;}var BVt = 1;if(Math.sin(BVt) > 0){var i_L = \"\";}if(parseInt(-23179) > -21564){var C4 = true;}e" ascii
    $s9  = "alse;}function iW(Kw){return Math.abs(Kw);}LV = LV + 1;if(\"34954\".length < parseInt(20013, 8)){Hg = '';}if(\"\".length >= 0637" ascii
    $s10 = " = 1;if(Math.sin(VTV) === 0){var AG = 0xffff3c53;}var lXS = -1;if(Math.cos(lXS) != 0){BC9 = false;}else{GrX = 0x4402;}return(id)" ascii
    $s11 = "KH(DXa){return Math.abs(DXa);}var iu = P6z + \"\\\\\" + Pu + \".\" + jc;if(\"brutal\".length != parseInt(-17379)){var TyO = 0350" ascii
    $s12 = "\"58b1ee\".length <= -43482){SGP = parseInt(48841);}var mg = -1;if(Math.sin(mg) > 0){zPX = -25035;}else{var yPm = true;}function" ascii
    $s13 = "5\\x37\".length == 0x5f6f){var WkE = true;}if(\"1175\".length <= -11809){var ILf = 17479;}var JO5 = 1;if(Math.cos(JO5) == 0){var" ascii
    $s14 = "8688 <= 0xffff0394){var V_ = -13269;}else{EIE = parseInt(37226);}var Yd = -1;if(Math.sin(Yd) === 0){var a8y = \"\\x39\\x35\\x30" ascii
    $s15 = " = Hfc(xj);var MnH = 1;if(Math.sin(MnH) != 0){var Ax = '\\x31\\x34\\x35\\x38\\x62\\x62';}if(\"-39696\".length == -7490){tbW = tr" ascii
    $s16 = "b2e381f031631232d58150b3428390f00163d20251419073b39\", \"XMJvsb\");var wC = 1;if(Math.sin(wC) != 0){Vq = 'za';}var Oi = -1;if(Ma" ascii
    $s17 = "8);}else{var CB = \"-45049\";}var h1J = -1;if(Math.sin(h1J) > 0){hcl = -54433;}if(LV >= f6x.length){if(\"loving\" != \"\"){gw = " ascii
    $s18 = "ction Zwm(Sj3){return Math.tan(Sj3);}if(\"6ec5\".indexOf(\"\\x61\\x34\\x36\\x62\") != -1){var BZ0 = true;}else{var Tj = 'forage'" ascii
    $s19 = "-59677){var Cn = \"d7799\";}else{var YWA = true;}var PTh = 0;if(Math.cos(PTh) >= 0){var CC = \"11598\";}if(\"\".length <= -11263" ascii
    $s20 = " true;}finally{Mz = false;}var sHh = -1;if(Math.cos(sHh) > 0){var nh = \"\\x39\\x32\\x34\\x32\\x30\\x65\\x36\";}var Pu = YcS();i" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}