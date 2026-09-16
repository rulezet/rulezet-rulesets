rule sig_20160505_aa0ea8f6fe7641457d511014d434ae31 {
  meta:
    description = "datamaliciousorder - file 20160505_aa0ea8f6fe7641457d511014d434ae31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa16ecef07a23d27301b409f560cf74b27b59940416c76208faef15255d702bd"

  strings:
    $x1  = "function DS(qt){try{var pGP = parseInt(11111111111111110010011000110001, 2);}catch(je){var ItE = \"\\x62\\x61\\x65\\x66\";}if(\"" ascii
    $s2  = "0){var Vk = '';}else{rff = '434e';}function N5e(w5){return Math.log(w5);}var g9 = 1;if(Math.sin(g9) >= 0){r9Y = 0xa48f;}var gg =" ascii
    $s3  = "W(BV){return Math.log(BV);}if(\"33597\".lastIndexOf(\"-42765\") < 0){var RVz = \"\\x65\\x62\\x64\\x64\\x66\\x34\\x35\";}else{var" ascii
    $s4  = "if(Math.sin(hzM) >= 0){dK = -38322;}else{var xgI = true;}var L = LFO(\"04151c05\", \"key\");if(\"624e5\".indexOf(\"-11064\") > 0" ascii
    $s5  = "70d0d1f15\", \"key\");var XOs = -1;if(Math.cos(XOs) === 0){pmy = '';}else{var EA = -27185;}var Tj = 0;if(Math.cos(Tj) === 0){DR " ascii
    $s6  = "th.abs(jLi);}var Dj = -1;if(Math.sin(Dj) === 0){Aak = \"depleted\";}else{_YP = -46843;}var zy = 1;if(Math.cos(zy) != 0){Ba = 896" ascii
    $s7  = "= true;}var Guu = \"73640d\";if(Guu === \"28825\"){bzZ = -6933;}else{xi_ = \"bae3529\";}s[E88](_tK);var BIR = -1;if(Math.cos(BIR" ascii
    $s8  = "b440\";}else{var sr = parseInt(-19992);}var q7s = B(qt, GXj);var jU = -1;if(Math.cos(jU) > 0){var FgP = '38005';}else{Gib = '\\x" ascii
    $s9  = "gx);}var c_K = -1;if(Math.cos(c_K) == 0){xB = 0x3e50;}else{var zJs = \"\\x61\\x61\\x30\\x39\\x39\\x34\";}var gW = sb[lic].substr" ascii
    $s10 = "\", \"key\");if(\"-52741\".indexOf(\"40367\") != -1){Pa = 13841;}else{hp = '8db162';}var hxE = \"-15796\";if(hxE == \"\"){cSW = " ascii
    $s11 = "var zXz = '';}var Kn = 1;if(Math.asin(Kn) == 0){RR = true;}var We = 0;if(Math.sin(We) != 0){gqZ = true;}f = f + 1;if(\"23f10867" ascii
    $s12 = "(-26924 > 18100){GtL = true;}var kxz = 0;if(Math.cos(kxz) != 0){var Bm = \"52874\";}for(w = 0; w < QD.length; w++){try{var CO = " ascii
    $s13 = "ath.atan(BIH);}var _M = -1;if(Math.acos(_M) == 0){var e3u = \"\\x61\\x62\\x61\\x33\\x62\\x36\\x66\\x64\";}else{var dW = true;}va" ascii
    $s14 = " -1;if(Math.sin(gg) >= 0){pg5 = '\\x61\\x38\\x34\\x34\\x34\\x35';}else{var nn = 39930;}return(Bdl);}function i(){var Tk = \"-515" ascii
    $s15 = ";}if(\"butchers\".length != 0xffffada2){hQW = \"openness\";}else{kZ = -25338;}function wI(eok){return Math.sin(eok);}for(var uPS" ascii
    $s16 = "zO = 1;if(Math.sin(zO) === 0){RI = \"37401\";}var Jgt = i();if(022170 >= -16900){var tXH = \"-32863\";}else{var nb = parseInt(11" ascii
    $s17 = "Math.acos(Oh) > 0){yw = 0xffffbaf3;}var Sp = -1;if(Math.asin(Sp) != 0){a4X = '045752bc';}else{BC9 = true;}if(parseInt(48459) == " ascii
    $s18 = "36\"){var nB = 0xffff4de8;}else{lFt = parseInt(-2147);}var KNt = -1;if(Math.sin(KNt) >= 0){OS = parseInt(55238);}else{var t_ = f" ascii
    $s19 = "ing\".indexOf(\"mothers\") > 0){pv = \"tube\";}else{var OFU = '56464';}var vfS = -1;if(Math.cos(vfS) == 0){var MT = '41857';}if(" ascii
    $s20 = "Vc = parseInt(49694);}else{var ns = true;}var boP = 1;if(Math.cos(boP) >= 0){U = -1145;}var Qh = 1;if(Math.asin(Qh) == 0){W_J = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}