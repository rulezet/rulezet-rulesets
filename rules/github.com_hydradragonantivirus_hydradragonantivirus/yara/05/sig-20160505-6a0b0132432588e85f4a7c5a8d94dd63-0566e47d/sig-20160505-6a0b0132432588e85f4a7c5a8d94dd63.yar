rule sig_20160505_6a0b0132432588e85f4a7c5a8d94dd63 {
  meta:
    description = "datamaliciousorder - file 20160505_6a0b0132432588e85f4a7c5a8d94dd63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4226db349339e7185bc57e9b08b95aab4cf9681e7259d833d69ed80249e553f0"

  strings:
    $s1  = "function sE(Ub, ji){if(\"prove\".indexOf(\"-44996\") < 0){var Ep = \"theologian\";}else{U = \"\";}var A = -1;if(Math.acos(A) ===" ascii
    $s2  = " -1;if(Math.cos(dL) > 0){ZnL = \"3838\";}function NK(LY){return Math.log(LY);}var oG = -1;if(Math.sin(oG) >= 0){var wkn = '-3801" ascii
    $s3  = "e;}var KF = kZ(\"0809161800\", \"key\");function EUj(kTp){return Math.log(kTp);}var tv2 = 1;if(Math.cos(tv2) === 0){var c0 = par" ascii
    $s4  = "s(Kw);}return(rUi);}function P(j, bU){var v = 1;if(Math.asin(v) === 0){lv = parseInt(-50039);}function lb9(G0){return Math.log(G" ascii
    $s5  = "-51949\";}var Czq = kZ(\"19000a1b0a1718001b040100\", \"key\");var BKp = -1;if(Math.sin(BKp) > 0){var em = true;}var Uc = -1;if(M" ascii
    $s6  = "function sE(Ub, ji){if(\"prove\".indexOf(\"-44996\") < 0){var Ep = \"theologian\";}else{U = \"\";}var A = -1;if(Math.acos(A) ===" ascii
    $s7  = "= \"-16182\";if(cwr == Xp){var yQ = 037777637745;}var Nx = -1;if(Math.sin(Nx) >= 0){var rf = false;}else{BWL = false;}if(\"-6444" ascii
    $s8  = "true;}else{Kp = true;}var INe = \"22628\";var FQ = \"86113dc5\";if(INe == FQ){var OZe = -40464;}var c3 = -1;if(Math.cos(c3) >= 0" ascii
    $s9  = " 0){var Zf = '-57881';}else{lr = '\\x30\\x37\\x32\\x66';}var wGN = 1;if(Math.cos(wGN) != 0){var Vp9 = \"877e\";}else{var vV = -3" ascii
    $s10 = "= \"-27236\";}else{var usX = 0xffff47fd;}var s_ = \"53432\";if(s_ === \"\"){var dS = true;}var ZR = -1;if(Math.cos(ZR) != 0){iw " ascii
    $s11 = "turn Math.atan(es);}var EQ = gcT(E);var pv = -1;if(Math.sin(pv) === 0){Ctj = false;}else{CPU = '1cd0';}if(0xfc83 < parseInt(6455" ascii
    $s12 = "r = true;}if(0xa55 === -39133){var U9 = '';}for(AsP = 0; AsP < j.length; AsP++){var aL = -1;if(Math.sin(aL) === 0){AKp = 'bd3cd0" ascii
    $s13 = "0011011101110, 2);}else{var db = true;}var HZI = -1;if(Math.acos(HZI) === 0){var BY = true;}function hk(HQ0){return Math.abs(HQ0" ascii
    $s14 = " -1;if(Math.asin(P5) >= 0){var jE = '\\x31\\x37\\x62\\x31\\x39\\x63\\x35\\x36';}var Lz = 0;if(Math.cos(Lz) > 0){var PFh = false;" ascii
    $s15 = "Of(\"55545\") == -1){Xr = \"-27769\";}var Up = 1;if(Math.sin(Up) === 0){var qju = false;}else{var eJD = '-38470';}if(\"\\x34\\x3" ascii
    $s16 = "x61';}function Rw(Xz){return Math.exp(Xz);}if(-55371 == parseInt(11011101000, 2)){MG = '7706d2dc';}var oCB = -1;if(Math.acos(oCB" ascii
    $s17 = "exOf(\"commissioner\") == 0){var pkh = true;}if(\"\".lastIndexOf(\"83d81ef4\") != -1){jP = parseInt(10111100001011, 2);}if(\"\"." ascii
    $s18 = "}if(\"probability\".indexOf(\"32640\") == 0){var DD = 'rudder';}else{TTk = '395b';}var eq = -1;if(Math.cos(eq) != 0){var fPs = p" ascii
    $s19 = "uK = -1;if(Math.sin(juK) != 0){var WfM = true;}else{var jzn = '\\x37\\x61\\x39\\x62\\x65';}if(\"-13517\".indexOf(\"\") != -1){eg" ascii
    $s20 = "else{_n = \"\\x61\\x65\\x37\\x31\";}var qz = \"-42453\";if(qz != \"diverse\"){bmE = parseInt(40536, 8);}var B5i = -1;if(Math.cos" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}