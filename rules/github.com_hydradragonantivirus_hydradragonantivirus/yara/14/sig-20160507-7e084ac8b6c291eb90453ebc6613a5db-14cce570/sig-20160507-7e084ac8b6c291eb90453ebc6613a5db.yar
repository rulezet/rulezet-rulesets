rule sig_20160507_7e084ac8b6c291eb90453ebc6613a5db {
  meta:
    description = "datamaliciousorder - file 20160507_7e084ac8b6c291eb90453ebc6613a5db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69ca35c31617450981231ce1575ae917e103c16af56fdb6b4295c0fa989335c9"

  strings:
    $s1  = "function v(r0, eE){if(\"\\x34\\x61\\x32\\x63\\x39\\x32\\x33\".indexOf(\"0e22f\") < 0){JmO = '-64891';}else{oF = true;}if(\"\\x39" ascii
    $s2  = "tN = \"aluminum\";}else{var wG = false;}return(AnM);}function R(){function MT(t){return Math.log(t);}var mxv = -1;if(Math.sin(mx" ascii
    $s3  = "(-301);}function XM(SW){return Math.log(SW);}function zD(WF){return Math.sin(WF);}var PrK = dTp(r0);function oy(c45){return Math" ascii
    $s4  = "r KM = \"vaccine\";}var X7 = 0;if(Math.cos(X7) >= 0){var Cv = '1cfead';}function Iq(Lnm){return Math.log(Lnm);}var HM = hy(\"362" ascii
    $s5  = " = '7f6e77';}else{var uQD = false;}xMU = xMU + 1;function Jc(Tn){return Math.sin(Tn);}var P = -1;if(Math.asin(P) == 0){var nN = " ascii
    $s6  = "ow = false;}var on = 1;if(Math.sin(on) != 0){dRA = 51604;}else{var mXD = false;}var Tu = -1;if(Math.asin(Tu) >= 0){var Rm = 'lea" ascii
    $s7  = "{var JPA = '-17439';}var bI = -1;if(Math.sin(bI) != 0){je = 010010;}else{var RAN = true;}if(\"909\".indexOf(\"\\x39\\x32\\x38\\x" ascii
    $s8  = ".length < -47736){var WA1 = true;}function IN(kDC){return Math.exp(kDC);}r0 += String.fromCharCode(parseInt(PrK.substr(fDD, 2), " ascii
    $s9  = "Of(\"\") == 0){He = '11181';}else{kY = \"41570\";}var g6Z = -1;if(Math.sin(g6Z) === 0){var dS = false;}return(_);}function dTp(P" ascii
    $s10 = "th.acos(Tqa) >= 0){kt = 'forbes';}else{var Jkr = 0x1255;}var eg = -1;if(Math.sin(eg) >= 0){lgc = false;}var VCI = -1;if(Math.cos" ascii
    $s11 = "f = -1;if(Math.cos(If) >= 0){var lQ = \"\";}else{_Rz = \"encouraged\";}if(\"0b105c\" != \"\"){Eyz = '\\x38\\x65\\x36\\x61\\x34" ascii
    $s12 = "th.cos(eq) === 0){var fPs = parseInt(-9937);}if(parseInt(-40873) > -24379){jIF = -11112;}else{Y7Q = \"\";}var g_ = \"ea4a443\";v" ascii
    $s13 = "ders';}else{var zz3 = \"\\x34\\x65\\x37\\x64\\x64\\x39\";}var fU = 0;if(Math.cos(fU) != 0){var wPm = -64579;}else{ht = parseInt(" ascii
    $s14 = "f(Math.cos(sa) != 0){var Xry = false;}if(\"-45021\".length <= -26393){bO = 037777623007;}var sC = 1;if(Math.asin(sC) > 0){var PH" ascii
    $s15 = "h.acos(Hny) != 0){var ZV = true;}function bv(Fe){return Math.abs(Fe);}var XV = -1;if(Math.asin(XV) >= 0){yC = '44049';}else{var " ascii
    $s16 = "29694;}var zPp = -1;if(Math.cos(zPp) >= 0){WZo = true;}var vSW = hy(\"3c025129\", \"Sr4Gvt6q\");var aT = 1;if(Math.sin(aT) > 0){" ascii
    $s17 = " = new ActiveXObject(T);if(\"replied\".length != -44870){var otQ = -14744;}function Ac(Qa){return Math.sin(Qa);}if(\"adult\".ind" ascii
    $s18 = "\"compatible\".lastIndexOf(\"30758\") == -1){azS = false;}else{YmR = '49624';}function fW(zVS){return Math.asin(zVS);}if(parseIn" ascii
    $s19 = "= 0){var iG = \"b6c76\";}else{WG = 41908;}var QPT = 0;if(Math.cos(QPT) >= 0){hOn = 30446;}else{Mx = \"6fc29754\";}var Kk = -1;if" ascii
    $s20 = "(\"og\") != -1){var NZ = \"\";}var MLh = 0;if(Math.sin(MLh) == 0){var kP = \"medallion\";}return(Q3p);}function l(){var Hny = 0;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}