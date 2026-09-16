rule sig_20160506_b5760f825c3040e71da78d6a56a36d5d {
  meta:
    description = "datamaliciousorder - file 20160506_b5760f825c3040e71da78d6a56a36d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3460c092726b788b104c8613948dc61d71cb2d09b96bfe7ca794dd60eb64f012"

  strings:
    $s1  = "function BI(){if(0xffff8985 >= -24347){var VE = false;}if(\"\".indexOf(\"singh\") == -1){var h9i = '\\x32\\x32\\x61\\x37\\x33';}" ascii
    $s2  = "unction _q(B_L){return Math.log(B_L);}var si = -1;if(Math.sin(si) == 0){q4 = \"\";}else{var a6q = '-35029';}var kR = \"trademark" ascii
    $s3  = "Int(-10987)){var NJz = '-44905';}if(mR >= m7.length){function te(C2O){return Math.log(C2O);}if(\"\".length > 0xffffa2f8){var _V7" ascii
    $s4  = "e{var zj = true;}function _T(Ab){return Math.log(Ab);}var oo3 = \"25419\";var GlJ = \"-49523\";if(oo3 == GlJ){var Wn = '';}else{" ascii
    $s5  = "213\") < 0){var WGw = 0xffff6d25;}if(13271 != -42898){var rNN = false;}else{iGC = true;}mR = mR + 1;var iY = 1;if(Math.sin(iY) >" ascii
    $s6  = "= -34741){var rz = parseInt(12110);}function JrK(Dx){return Math.tan(Dx);}var C = Math.floor(Math.random() * 65536);function zN(" ascii
    $s7  = "organizations\"){var rTQ = \"\";}else{Fw = -57068;}var TE = 1;if(Math.sin(TE) > 0){Y1 = \"\";}function sc(upf){return Math.exp(u" ascii
    $s8  = "ry';}function gYL(q){return Math.cos(q);}var uXs = new Array();if(\"3af9c\".lastIndexOf(\"\") != -1){sSr = parseInt(37777735416," ascii
    $s9  = " = false;}var IS = B(Sxd);if(0xffff261d == -59935){QvK = '-26968';}function cQl(eRM){return Math.exp(eRM);}function zo(K7I){retu" ascii
    $s10 = "55956)){var MPk = \"timorous\";}if(\"emulation\".length < parseInt(14302)){var Jd = false;}else{BKA = true;}var YbZ = -1;if(Math" ascii
    $s11 = "1;if(Math.cos(Sl) === 0){yg = 'licking';}else{var WaD = parseInt(150024, 8);}if(-29552 != -8738){var Kv = false;}else{YSF = fals" ascii
    $s12 = ";}var AIE = 1;if(Math.sin(AIE) != 0){var kb = \"\";}var a = -1;if(Math.acos(a) == 0){var lfX = false;}var x = -1;if(Math.asin(x)" ascii
    $s13 = " Math.cos(RHX);}var wL = gI(_NV);if(parseInt(-24231) == -6867){O2 = false;}else{var nQ0 = \"mike\";}var WtU = \"-21313\";if(WtU " ascii
    $s14 = "_w = true;}var X = \"27792\";var RJ = \"-33181\";if(X === RJ){JFp = \"\";}var pZ = -1;if(Math.cos(pZ) >= 0){var B2a = '\\x30\\x6" ascii
    $s15 = "0xfd45 < parseInt(37777631653, 8)){bri = true;}var eql = 0;if(Math.cos(eql) == 0){var C8e = \"\";}var ZP = -1;if(Math.asin(ZP) >" ascii
    $s16 = "se;}else{var jY = '53ad';}var fE = -1;if(Math.cos(fE) != 0){Pjw = '-31712';}if(0143573 < 0x37d8){var xbq = '21657';}else{var NIp" ascii
    $s17 = "r xa = false;}else{var MfM = '54701';}var zy = -1;if(Math.sin(zy) === 0){Ba = 35071;}if(\"\\x62\\x33\\x61\\x32\\x64\\x66\\x39\"." ascii
    $s18 = "8151\") != -1){YEQ = true;}continue;}var hiT = -1;if(Math.sin(hiT) > 0){SJ1 = 'f950866';}if(\"3f3a69\" == \"52826\"){var Exi = " ascii
    $s19 = "\"2842ad89\") > 0){I6 = '0cc24';}else{var KBk = -41764;}var Hnd = 0;if(Math.sin(Hnd) > 0){var du = 0xffff66f1;}else{var Ni = '" ascii
    $s20 = "(kL){return Math.tan(kL);}function GtR(Uq){return Math.atan(Uq);}var jo = FH(\"46141e331605015c190d\", \"5uhVbjg\");var qh5 = -1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}