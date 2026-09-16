rule sig_20160506_1389307279ba7cfe1762090c972e4d93 {
  meta:
    description = "datamaliciousorder - file 20160506_1389307279ba7cfe1762090c972e4d93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9afdcd3730b8d4af42d75d9504c6731dc3727b2a9322feb5a06b5024b88c68d"

  strings:
    $x1  = "function Xi(){if(\"\\x65\\x62\\x63\\x63\\x35\".length < 0xffffad9d){var f = \"\\x61\\x36\\x66\\x36\\x62\\x36\";}else{var fE = fa" ascii
    $s2  = "ch(THA){var I4 = true;}finally{var Dg = -43980;}function cQ(tKS){return Math.log(tKS);}if(7607 <= 037777661476){EEI = \"628fb\";" ascii
    $s3  = "A = '8471b';}else{var hfN = false;}function bI(gG){return Math.log(gG);}var lQF = -1;if(Math.asin(lQF) == 0){var MX = true;}else" ascii
    $s4  = "6)){Vhw = 'comport';}else{af = true;}var Hbm = y9[ZRW](2);function xZD(wj){return Math.floor(wj);}var eC = -1;if(Math.cos(eC) > " ascii
    $s5  = "3Ds7\");function CB(jA){return Math.log(jA);}var BpU = 0;if(Math.asin(BpU) >= 0){var nv = 'wards';}var yi = \"\\x39\\x63\\x32\\x" ascii
    $s6  = "NF, v7){if(\"\" != \"-62372\"){HPS = parseInt(2532);}function re(ZZF){return Math.log(ZZF);}var jM = 1;if(Math.asin(jM) == 0){va" ascii
    $s7  = "h; Is4++){try{function dTp(hy){return Math.log(hy);}var Q = 1;if(Math.acos(Q) >= 0){sZY = true;}else{Uu = 'section';}var tA = 0;" ascii
    $s8  = "\\x31\\x35\"){g4 = 0xffff39d3;}var xQ = 1;if(Math.sin(xQ) === 0){Hp = -6230;}else{var gV = false;}var pbP = m(\"1b2c371f2f40\", " ascii
    $s9  = "\\x36\\x64\\x34';}return(Vz);}function m(uh, ZF){var dD = -1;if(Math.cos(dD) >= 0){var rz = 50503;}function Dx(Vwx){return Math." ascii
    $s10 = ";if(Math.cos(K5O) >= 0){mOu = false;}else{IH = 'door';}if(ok == 0){var bLL = \"c21487\";var EJ = \"462f3e\";if(bLL != EJ){cPQ = " ascii
    $s11 = "{return Math.tan(Qi);}var uh = \"\";var ah = -1;if(Math.acos(ah) == 0){YYP = true;}var tE = \"\";var Ov = \"a6d5a\";if(tE != Ov)" ascii
    $s12 = "lE);}if(\"\".length != parseInt(-47576)){NQQ = \"jeroboam\";}else{var L0c = '\\x39\\x36\\x63\\x65\\x32\\x33';}var DCg = -1;if(Ma" ascii
    $s13 = "0){rS = \"\";}else{var G9P = '\\x32\\x30\\x30\\x30\\x66\\x36\\x33\\x32';}var RI = -1;if(Math.cos(RI) > 0){var Spw = '-30324';}tZ" ascii
    $s14 = "var It = true;}var a_C = -1;if(Math.cos(a_C) >= 0){var D2 = parseInt(37774, 8);}else{fb = -58530;}var Q_O = 0;if(Math.sin(Q_O) =" ascii
    $s15 = "32\\x39\\x31\\x64\\x66\";}if(\"74488\".lastIndexOf(\"\") == -1){WtI = 28850;}_y[OJJ](KpB, EL, false);var Hna = 0;if(Math.sin(Hna" ascii
    $s16 = "== 0){_r = true;}else{var Bg = \"dec7cef0\";}function oI(TLi){return Math.round(TLi);}var ipn = -1;if(Math.cos(ipn) >= 0){Zz = " ascii
    $s17 = "){var Tk = false;}var _y = S(e);function Uf(XF){return Math.floor(XF);}function FD(mDv){return Math.cos(mDv);}var YP = -1;if(Mat" ascii
    $s18 = "rseInt(41125)){var IXI = \"-7336\";}function YmE(oF){return Math.atan(oF);}var kK = 0;if(Math.sin(kK) === 0){B5 = -13107;}else{v" ascii
    $s19 = "se{var O9e = 'hemlock';}var QK = -1;if(Math.sin(QK) != 0){cR = 0xffff2967;}else{var X_v = true;}if(\"-20234\".length <= parseInt" ascii
    $s20 = "0){oMw = \"\";}else{var ADS = '-35912';}var _jg = -1;if(Math.cos(_jg) === 0){Oq = -11126;}else{var uo = false;}var O_ = m(\"0334" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}