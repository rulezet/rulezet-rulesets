rule sig_20160505_737fdc99ef10d48e840ca9844bb0bfda {
  meta:
    description = "datamaliciousorder - file 20160505_737fdc99ef10d48e840ca9844bb0bfda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38a0ed0869db9e13e2287c43da69a59c3d4b3cd9067728704db7e7ad43c2ced4"

  strings:
    $x1  = "function Al(xtu){var N = 0;if(Math.sin(N) > 0){var h = true;}else{var Xi = 0xc6b6;}if(\"40540\" == \"-48144\"){var hk = parseInt" ascii
    $s2  = "H){return Math.log(T4H);}var tKu = \"7812\";if(tKu === \"naturally\"){pYP = -635;}var RKN = 1;if(Math.cos(RKN) > 0){IY = '55536'" ascii
    $s3  = "acos(Zk) > 0){Hg = '34456';}function _fZ(AX){return Math.log(AX);}var tFQ = \"\";if(tFQ === \"28019\"){n6 = \"46976\";}else{var " ascii
    $s4  = " Math.log(QI);}function x2(bj){return Math.ceil(bj);}if(24616 < parseInt(100111100011111, 2)){var uq = '';}else{ft = '-4566';}re" ascii
    $s5  = "Math.abs(kb);}var THZ = Pm(nH);var fai = \"-34201\";if(fai != \"\"){zhD = \"14409\";}if(\"002f\" != \"\"){ee = false;}else{M8z =" ascii
    $s6  = " 2);}else{ddP = '1effd2a';}if(\"javascript\".length != 037777733625){var WQ = true;}var aP = -1;if(Math.acos(aP) != 0){aM1 = tru" ascii
    $s7  = "Math.cos(K_3);}var pn = nZ(\"1f1c090e\", \"key\");function bV(pZ){return Math.acos(pZ);}var cYv = \"dev\";var Jul = \"-27691\";i" ascii
    $s8  = "turn(U1C);}function nZ(ce9, UM6){if(\"28372\".lastIndexOf(\"\\x65\\x30\\x39\\x61\\x30\\x61\\x32\") > 0){yb = \"\";}else{var dCG " ascii
    $s9  = "X != IHG){FdF = -64873;}else{var ltJ = true;}var KDX = 0;if(Math.sin(KDX) == 0){sq = \"6d628fa\";}else{var HwZ = '-1395';}var BI" ascii
    $s10 = ";var m6 = -1;if(Math.cos(m6) >= 0){fkH = false;}var cNg = 1;if(Math.sin(cNg) >= 0){vs = parseInt(37124);}function ADK(QI){return" ascii
    $s11 = "654, 8);}else{u9j = 'abodes';}if(\"11784\".indexOf(\"-49974\") == 0){var tu = '';}else{RIw = '16650';}var lW = -1;if(Math.cos(lW" ascii
    $s12 = " \"48668\";}if(\"\".lastIndexOf(\"\\x39\\x34\\x31\\x39\") == -1){lrN = true;}else{aNq = 'laos';}var Vm = -1;if(Math.sin(Vm) === " ascii
    $s13 = "11111111111110100011110110001, 2);}else{ISk = parseInt(-61810);}var U = 0;if(Math.cos(U) != 0){PJO = -15880;}else{MFi = \"\\x34" ascii
    $s14 = "}else{var gR = true;}var C_ = -1;if(Math.acos(C_) === 0){var R4L = \"taketh\";}var G = nZ(\"1c161a190c091f4b0a03001507\", \"key" ascii
    $s15 = " = '';}var lD = 1;if(Math.sin(lD) === 0){J8 = false;}if(\"53546\".indexOf(\"\\x66\\x35\\x32\\x37\\x62\\x62\\x35\") == -1){var Ww" ascii
    $s16 = "621){var l2w = \"seraphic\";}else{var ZN = -22042;}var eYV = 1;if(Math.sin(eYV) != 0){WS = 36331;}else{var IOk = false;}var BJ =" ascii
    $s17 = "reehold\") == 0){kcJ = '61410';}function Ec(GQX){return Math.tan(GQX);}var pJ = -1;if(Math.cos(pJ) != 0){var Lxv = 'killed';}D18" ascii
    $s18 = "= \"17842\";}var Wg = Pm(KZ);if(\"\".length == -52183){dR = true;}else{var EJ = \"\\x34\\x61\\x62\\x65\\x38\\x61\";}var Ant = -1" ascii
    $s19 = "Int(100100100110111, 2)){var Y_I = true;}function A8k(b, jm){return Math.atan2(b, jm);}var TYf = -1;if(Math.sin(TYf) == 0){var d" ascii
    $s20 = "{var Did = \"19912\";}Z = 0;}}var GIO = -1;if(Math.acos(GIO) >= 0){var Poi = true;}function d2k(BZR){return Math.exp(BZR);}var T" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}