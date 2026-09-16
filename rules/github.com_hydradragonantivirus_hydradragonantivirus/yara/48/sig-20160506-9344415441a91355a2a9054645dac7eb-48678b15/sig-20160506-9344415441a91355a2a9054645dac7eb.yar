rule sig_20160506_9344415441a91355a2a9054645dac7eb {
  meta:
    description = "datamaliciousorder - file 20160506_9344415441a91355a2a9054645dac7eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "818d949805398fa1b50391395e8ad41398ed69138160d075d2545c27d2deb645"

  strings:
    $s1  = "function gFR(E, iLM){if(30311 < 45755){s02 = -28129;}else{rf = \"08058bf\";}var S = 0;if(Math.acos(S) == 0){var AVc = '8621cddd'" ascii
    $s2  = "Oyl);}function B9b(W1, wc4){return Math.atan2(W1, wc4);}function uET(d9){return Math.log(d9);}var RWa = 1;if(Math.acos(RWa) >= 0" ascii
    $s3  = "tion jyb(FD){return Math.tan(FD);}function Gu(yK){return Math.log(yK);}var uS = pY(\"0a131a1c1b3c1d561e5e0e1c072d07410a040d18042" ascii
    $s4  = "e\";if(DCg == \"-30849\"){var bsz = true;}else{var mo = '-48591';}X = X + 1;var sZ = 1;if(Math.sin(sZ) === 0){var zwt = -23219;}" ascii
    $s5  = "\\x65\\x39\\x31';}else{zv = '-37850';}if(\"-9468\".indexOf(\"52001\") == -1){DJk = -64973;}var Wb = -1;if(Math.cos(Wb) > 0){var " ascii
    $s6  = "(jRL) === 0){sE = true;}else{var AL = \"045a55c4\";}var SQj = -1;if(Math.cos(SQj) == 0){var WA1 = true;}else{var wQ = '';}x8 += " ascii
    $s7  = "(Math.cos(B_L) === 0){tb = '';}if(parseInt(52125) >= -32117){RI = \"cb7f08e1\";}else{var RHX = 'pizza';}for(rTQ = 0; rTQ < x8.le" ascii
    $s8  = ";}var PZr = 1;if(Math.asin(PZr) != 0){QrQ = \"48719\";}else{var IO2 = '56054';}function ZBC(Lp6){return Math.abs(Lp6);}var XHT =" ascii
    $s9  = "n Math.acos(jP);}var g3 = 0;if(Math.sin(g3) == 0){var Ji = 'interim';}else{KX = '20689';}var MiD = -1;if(Math.cos(MiD) >= 0){dKH" ascii
    $s10 = "= false;}var hR = 1;if(Math.cos(hR) == 0){Ia = true;}else{pFF = 45056;}var nE = h + \"\\\\\" + y3 + \".\" + P5i;function esV(jP)" ascii
    $s11 = "alse;}else{var pMp = -33392;}var yt = 0;if(Math.asin(yt) >= 0){var I9 = \"-24265\";}var qz = 0;if(Math.sin(qz) === 0){var fyE = " ascii
    $s12 = "r r_8 = -201;}var ZP = 0;if(Math.cos(ZP) != 0){var V7 = false;}var INF = -1;if(Math.cos(INF) >= 0){jcE = '48090e33';}else{wmD = " ascii
    $s13 = "eil(Mx);}function dP(WR){return Math.abs(WR);}var oU = 0;if(Math.acos(oU) > 0){var ki = parseInt(-52434);}else{B5 = -28917;}var " ascii
    $s14 = "x39\\x35\\x34\\x39\\x34\\x62\\x34\") != -1){ZVX = \"colloquy\";}else{DO = 0xffff16e1;}var yx = 1;if(Math.asin(yx) === 0){var AKp" ascii
    $s15 = ";}else{Kn = '-5490';}function HZ(Dg){return Math.abs(Dg);}var l54 = \"\";var MgO = \"-41844\";if(l54 == MgO){var VFA = -1791;}el" ascii
    $s16 = " = false;}if(\"-18665\".lastIndexOf(\"-17309\") == 0){var EP = '\\x61\\x33\\x65\\x38\\x30\\x65\\x36';}var N7 = -1;if(Math.sin(N7" ascii
    $s17 = "078;}var sy = -1;if(Math.acos(sy) == 0){C8U = \"\";}else{var pHk = '';}var ya = 0;if(Math.cos(ya) === 0){tV = \"3f5db4\";}else{v" ascii
    $s18 = "tA);}function SY(){var eH = -1;if(Math.sin(eH) == 0){Fw = true;}if(-37467 >= -35248){wSK = '27123';}function z(Mx){return Math.c" ascii
    $s19 = " MA = -1;if(Math.cos(MA) === 0){var rI = \"-46129\";}function Fnw(vCW){return Math.tan(vCW);}var TZ = \"64903\";if(TZ != \"5874" ascii
    $s20 = "(JFt === \"\"){rm = \"1113\";}else{var cu = '';}var LM = \"2a79\";var cqL = \"\";if(LM == cqL){var e_T = false;}var M8g = -1;if(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}