rule sig_20160506_4323e467a476e563874cd07f5f5f7586 {
  meta:
    description = "datamaliciousorder - file 20160506_4323e467a476e563874cd07f5f5f7586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64edfa7387567488aaf04ec9c1e7534e9d6d64e7e8a0a8ca007bae708b628192"

  strings:
    $x1  = "function t(fNv, yxN){var vH = -1;if(Math.asin(vH) == 0){var XC = false;}var hR = -1;if(Math.sin(hR) === 0){p = \"8779\";}else{hs" ascii
    $s2  = "rseInt(39392)){C2O = 'mit';}function aJC(Xd){return Math.log(Xd);}var RZe = 1;if(Math.asin(RZe) > 0){var umF = 0xffffcea3;}funct" ascii
    $s3  = "9120\";}if(\"4581c9c\" != \"4096\"){var VO = false;}function JqJ(RNV){return Math.log(RNV);}fJ5[axk]();var i28 = 1;if(Math.asin(" ascii
    $s4  = "M = oE(\"5e1c101b1d222f5018080e022b285c0b\", \"9ydhmGL\");var Bol = -1;if(Math.cos(Bol) != 0){var ilX = '10088c';}else{var fDD =" ascii
    $s5  = "(ID) === 0){var BfL = parseInt(29632);}var HWN = 1;if(Math.sin(HWN) === 0){Xp = 'infect';}function gM(dad, ERr){return Math.atan" ascii
    $s6  = "mq = true;}else{var gUS = \"\\x36\\x64\\x34\\x63\";}var QMQ = 1;if(Math.asin(QMQ) == 0){Qy = true;}else{var PV = -24637;}xj = xj" ascii
    $s7  = "}else{wlI = \"58224\";}var m3i = 0;if(Math.asin(m3i) == 0){oVM = \"bats\";}else{wx = -22571;}var L1Z = 1;if(Math.sin(L1Z) === 0)" ascii
    $s8  = "Int(37777600257, 8)){var UT = false;}var bY = -1;if(Math.sin(bY) != 0){var JGs = 'diablo';}var aJG = 0;if(Math.asin(aJG) == 0){Q" ascii
    $s9  = "dexOf(\"dormitory\") == 0){var wXA = '-29513';}else{var eXR = true;}var Vb = -1;if(Math.sin(Vb) === 0){var uq = '2488';}else{ft " ascii
    $s10 = "i9 = -1;if(Math.cos(xi9) == 0){uT = '\\x35\\x64\\x35\\x65';}else{jXL = '\\x62\\x64\\x39\\x31\\x61\\x34\\x33\\x34';}if(parseInt(-" ascii
    $s11 = " -1){xv = '30538';}J[UP]();var BaY = 1;if(Math.asin(BaY) == 0){deL = true;}var SBr = 0;if(Math.sin(SBr) >= 0){var pP = \"-33666" ascii
    $s12 = "ndexOf(\"\\x64\\x39\\x64\\x34\") == 0){var Fr = true;}var hAM = -1;if(Math.sin(hAM) != 0){YN = '33678';}else{var pf = 43041;}var" ascii
    $s13 = "1';}var hM = 0;if(Math.acos(hM) >= 0){var Zm = '33292';}var Dez = -1;if(Math.sin(Dez) >= 0){DJk = 0xffff29d8;}var Wb = 1;if(Math" ascii
    $s14 = "h.cos(gn3) > 0){nFb = false;}fJ5[v_]();if(\"exam\".length != 34986){FR = '';}else{nt = \"15836\";}var Ghg = -1;if(Math.acos(Ghg)" ascii
    $s15 = "cb9\";}else{var Wrj = 0xb995;}var gJ = 0;if(Math.sin(gJ) > 0){JPA = 0172465;}if(\"56198\".indexOf(\"e809\") == 0){FZy = -42789;}" ascii
    $s16 = "ndexOf(\"-6227\") == -1){Uz = true;}else{var SJ = \"5248e7\";}var z = oE(\"1704193d3822005f0800\", \"deoXLMf6\");var yS = 1;if(M" ascii
    $s17 = "nt(15125, 8);}else{YxX = '';}function Cv(y6P){return Math.tan(y6P);}var b = Rzd[K].split(\"|\");if(\"\".lastIndexOf(\"-40590\") " ascii
    $s18 = "QUN = true;}else{lnf = false;}var Wq = -1;if(Math.cos(Wq) != 0){var dZd = true;}else{var MxU = '53382';}var aue = -1;if(Math.aco" ascii
    $s19 = "e;}else{var Nwh = '\\x63\\x39\\x36\\x32\\x37\\x36\\x37\\x39';}var Edc = \"\\x31\\x34\\x32\\x34\\x61\\x32\\x38\";if(Edc == \"comi" ascii
    $s20 = "tion C_x(Cu){return Math.tan(Cu);}function BN(ph){return Math.ceil(ph);}if(\"tandem\".lastIndexOf(\"\\x34\\x31\\x31\\x63\\x34\")" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}