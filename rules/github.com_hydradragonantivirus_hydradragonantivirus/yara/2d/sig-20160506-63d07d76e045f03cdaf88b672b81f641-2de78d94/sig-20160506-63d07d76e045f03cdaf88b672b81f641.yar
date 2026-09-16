rule sig_20160506_63d07d76e045f03cdaf88b672b81f641 {
  meta:
    description = "datamaliciousorder - file 20160506_63d07d76e045f03cdaf88b672b81f641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63d0afc766f2a7cc8fd15921741a4f178233b5286b3175614b389bcce48124e6"

  strings:
    $x1  = "function pc(gQ, Sha){var Z = 0;if(Math.cos(Z) >= 0){var jE2 = 0xffff5727;}else{var ay = \"inch\";}var cph = -1;if(Math.acos(cph)" ascii
    $s2  = "(Mi);}function dfg(VU){return Math.log(VU);}function j3(gNy){return Math.log(gNy);}return(bbi);}function Y8(RsX, ud){if(\"\" == " ascii
    $s3  = "else{UA = true;}function xs5(Ekq){return Math.log(Ekq);}var EI = 1;if(Math.acos(EI) === 0){fY = true;}else{var VH = \"\\x39\\x36" ascii
    $s4  = "r x = E[VGh].substr(0, 2);function cNg(yca){return Math.acos(yca);}function Wb(QH0){return Math.log(QH0);}if(0xffff5ccb >= -3382" ascii
    $s5  = "g = 'crop';}var yS = -1;if(Math.sin(yS) >= 0){var ur_ = true;}else{Qe = true;}var nH = KZ + \"\\\\\" + Vh + \".\" + Wg;if(-5727 " ascii
    $s6  = "\\x33\\x62\";}if(\"\".length < -2220){var vLJ = false;}var T = pc(\"165d5e14\", \"e80pWS\");var SL = \"21038\";var p6 = \"sausag" ascii
    $s7  = "ath.cos(kzM) > 0){lv = 0xffffccb5;}if(0xa6b1 != -20407){var IOk = 36907;}var Ab = -1;if(Math.asin(Ab) > 0){var oS = false;}if(\"" ascii
    $s8  = " === 0){Nge = false;}else{HlB = '50893';}var BH = -1;if(Math.cos(BH) === 0){var rGO = \"62336\";}var Ite = 0;if(Math.acos(Ite) >" ascii
    $s9  = "if(Math.cos(YM) === 0){var No = parseInt(40517, 8);}function tD(bZX){return Math.acos(bZX);}var ug = -1;if(Math.asin(ug) === 0){" ascii
    $s10 = "= false;}else{Zh = parseInt(-516);}function DlX(HW){return Math.tan(HW);}var xs = -1;if(Math.asin(xs) === 0){hg = \"\\x63\\x63" ascii
    $s11 = "x\");function qD(RFJ){return Math.ceil(RFJ);}var Tk = -1;if(Math.sin(Tk) > 0){var r5G = false;}var Hp_ = 0;if(Math.sin(Hp_) === " ascii
    $s12 = "{bwb = \"\";}var mpx = -1;if(Math.cos(mpx) >= 0){var Ju = true;}var bY = 0;if(Math.acos(bY) === 0){var uA = -11363;}else{wOy = p" ascii
    $s13 = "{function R(h){return Math.ceil(h);}var Aw = 1;if(Math.cos(Aw) != 0){eJ = false;}else{var aM = '0410';}var ih = -1;if(Math.sin(i" ascii
    $s14 = "x35\\x37\\x64\\x65\\x36\\x34\\x31\".indexOf(\"\\x35\\x65\\x36\\x39\\x66\\x64\\x61\") == -1){k2 = 0xffff1b94;}function s0(bVK){re" ascii
    $s15 = "}var kNV = 1;if(Math.cos(kNV) == 0){var Fk = true;}else{var QiJ = -52459;}}}}function ui(){var hN = -1;if(Math.sin(hN) != 0){a3 " ascii
    $s16 = "function pc(gQ, Sha){var Z = 0;if(Math.cos(Z) >= 0){var jE2 = 0xffff5727;}else{var ay = \"inch\";}var cph = -1;if(Math.acos(cph)" ascii
    $s17 = "\";}return(Vh);}function e(zF0){var Yo = -1;if(Math.sin(Yo) > 0){var mo = 10590;}else{HO = 0x684;}if(31849 == 49579){var S0 = tr" ascii
    $s18 = "yzp\");var A7Z = 1;if(Math.sin(A7Z) != 0){var b6 = \"2d91\";}else{ThI = \"17565\";}if(0xcb0e == parseInt(32544)){FH = -49049;}el" ascii
    $s19 = "4009\";}return(AT);}function cIF(uW){var h_ = -1;if(Math.acos(h_) === 0){Cw = true;}var YZ = 1;if(Math.sin(YZ) > 0){Gmv = -30019" ascii
    $s20 = "var zbW = false;}var II = 0;if(Math.cos(II) > 0){var pZ = true;}else{var oPL = -45944;}var Ph = -1;if(Math.cos(Ph) > 0){var U7j " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}