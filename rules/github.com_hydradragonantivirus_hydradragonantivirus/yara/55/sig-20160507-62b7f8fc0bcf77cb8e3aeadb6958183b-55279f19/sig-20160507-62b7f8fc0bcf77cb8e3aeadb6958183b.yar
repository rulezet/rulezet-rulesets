rule sig_20160507_62b7f8fc0bcf77cb8e3aeadb6958183b {
  meta:
    description = "datamaliciousorder - file 20160507_62b7f8fc0bcf77cb8e3aeadb6958183b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c34b8059b1543b3462e4b73e595e4c24629c01c9ebea9e82fe2769f8069bddf"

  strings:
    $x1  = "function tB(MBS, wk){if(-46999 != 037777714114){var u = 'richie';}else{var rXe = \"-4696\";}var aJC = 0;if(Math.cos(aJC) === 0){" ascii
    $s2  = " iO = \"-441\";if(iO === \"-50392\"){xu = -41810;}var UqB = \"injection\";if(UqB != \"\\x65\\x31\\x39\\x36\"){var Px = 'grab';}e" ascii
    $s3  = "e;}if(\"-32525\".length != parseInt(23544)){BsF = '';}function OX(C5J){return Math.log(C5J);}var His = 0;if(Math.sin(His) >= 0){" ascii
    $s4  = "eturn Math.log(CH);}function Hg(Iba, sN){return Math.atan2(Iba, sN);}var xs5 = \"\";if(xs5 != \"61412\"){sgA = true;}function ZA" ascii
    $s5  = "}else{var R2n = true;}function EA(tF){return Math.log(tF);}var t3C = f(\"44263f051e0c1604542c280c\", \"6CLuqbea\");function EV(C" ascii
    $s6  = "sU){return Math.log(QsU);}if(-34936 == 7701){var I9 = \"\";}var azt = Tju[t3C];if(\"broth\".length === parseInt(37777775444, 8))" ascii
    $s7  = "(wa);}function Biv(iG){return Math.log(iG);}var Tju = Ueo(Dl);var XLj = \"a052f1\";if(XLj != \"700\"){var Fr = true;}else{WN = f" ascii
    $s8  = ";}else{var _m = true;}var Yz = -1;if(Math.sin(Yz) > 0){var wLJ = true;}if(\"portfolio\".length === 0x86de){var Idd = '\\x64\\x31" ascii
    $s9  = "tion uK(ye, lw){var gR = \"basal\";if(gR === \"\"){FG = false;}else{var mfk = \"frames\";}var dUA = -1;if(Math.sin(dUA) != 0){va" ascii
    $s10 = "\\x31\\x35';}var Ql = 0;if(Math.asin(Ql) != 0){var C8e = \"-18551\";}else{var r_8 = -14202;}var IGB = KXP + \"\\\\\" + zy + \"." ascii
    $s11 = "if(\"\".length >= -38450){var NL = false;}else{cW = false;}function yL(hTH){return Math.abs(hTH);}if(\"\\x36\\x63\\x66\\x65\\x30" ascii
    $s12 = "qHI) >= 0){var gUU = 0xba8e;}else{KQ = parseInt(61388);}var THA = -1;if(Math.cos(THA) > 0){var Ys = '49046';}else{Avv = '\\x30" ascii
    $s13 = "ath.acos(mV) > 0){var mCm = '';}else{var fR = true;}if(28994 > 0176245){Bbm = 0xffff0d29;}if(021741 == -40921){var WkE = true;}v" ascii
    $s14 = "x64\\x62\\x62\\x32\\x36\\x35\\x66\\x30';}else{NVh = '11685';}var hy = -1;if(Math.sin(hy) > 0){var lNL = parseInt(-50507);}else{Y" ascii
    $s15 = "){var iHE = 'terminal';}else{var jQ = false;}var KXP = d[gx](2);var cK = -1;if(Math.cos(cK) != 0){var wFP = \"debe236\";}if(\"db" ascii
    $s16 = "= '34412';}var tFQ = hfe[3];var ZJm = 0;if(Math.sin(ZJm) != 0){var lfX = true;}var Guq = -1;if(Math.cos(Guq) != 0){var tC = 3248" ascii
    $s17 = "X = -1;if(Math.sin(bX) > 0){yBr = true;}else{jb = '';}var Sg = 1;if(Math.asin(Sg) === 0){lo1 = -50618;}var PYw = 0;if(Math.acos(" ascii
    $s18 = "85\".length > -63327){GrX = parseInt(-27647);}var Ekk = 1;if(Math.cos(Ekk) != 0){var kk = true;}else{md = true;}var zy = xc();if" ascii
    $s19 = "h.cos(qH) === 0){IW = false;}else{var rK = \"2abbb67d\";}if(\"ao\".length === -30537){fQ = true;}var EH = 0;if(Math.acos(EH) != " ascii
    $s20 = "eInt(57455)){lgc = \"5000a\";}if(53366 >= -9611){var eL = '25875';}else{var mss = \"\";}var yQ = 0;if(Math.cos(yQ) === 0){Thj = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}