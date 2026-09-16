rule sig_20160506_32c544e5b840a56067e302a7e5763c3d {
  meta:
    description = "datamaliciousorder - file 20160506_32c544e5b840a56067e302a7e5763c3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b17f103788312e683d78bfbdf167dc40be3db2fa5b52c2168f99bbe989034a87"

  strings:
    $x1  = "function H_u(){if(\"18884\" == \"goth\"){E = false;}if(\"-31704\".length > -37284){var jE = '\\x33\\x39\\x33\\x33';}else{N = '" ascii
    $s2  = "rn Math.log(jq);}var M = HNf(\"2819383c50\", \"KuWO58\");var ZZF = -1;if(Math.cos(ZZF) != 0){var TR = 0xffff50a2;}else{w1 = pars" ascii
    $s3  = "eturn Math.round(z1X);}function qf(TC){return Math.atan(TC);}function P1h(a4){return Math.log(a4);}var gL = -1;if(Math.sin(gL) >" ascii
    $s4  = "rue;}else{Sx6 = 'undisciplined';}var S1g = -1;if(Math.sin(S1g) > 0){xvw = false;}else{cd = 'log';}}}}function fG(T){if(\"67012\"" ascii
    $s5  = "ath.sin(sub) > 0){tOz = \"7e57\";}else{var SZ = '13864';}if(\"53504\".indexOf(\"39635\") == -1){var i_ = '';}if(\"2012\" === \"b" ascii
    $s6  = "\\x39\\x38\\x61\\x33\\x32\\x34\") != -1){var aX = \"15506\";}var snN = -1;if(Math.sin(snN) != 0){EW = '';}else{qT = \"\";}if(\"8" ascii
    $s7  = "';}function gP(XKz){return Math.acos(XKz);}Noi = Noi + 1;if(\"-1691\".length == -50535){var EXf = parseInt(23412, 8);}else{var G" ascii
    $s8  = "cos(IOX) == 0){a8A = '-48741';}else{ljs = true;}var Zk = 0;if(Math.cos(Zk) >= 0){od = true;}else{var bT = \"d880\";}var U7 = -1;" ascii
    $s9  = "At(Noi));var mQ = -1;if(Math.sin(mQ) != 0){qz = false;}if(\"\" == \"\\x64\\x36\\x33\\x65\\x30\\x33\"){var WA1 = true;}else{var w" ascii
    $s10 = " HNf(\"00252a5e\", \"oUO0MTC\");var VUl = -1;if(Math.cos(VUl) != 0){AIE = \"18177\";}else{LY = -52932;}if(\"-168\" === \"55424\"" ascii
    $s11 = "(\"0d1362\", \"JV6rT9\");function pij(kcJ){return Math.tan(kcJ);}if(-11393 === parseInt(-46265)){IW = \"55fc6a1a\";}var NL = -1;" ascii
    $s12 = "tion Vj(ZT){return Math.cos(ZT);}var ft = HZA(T, sxe);if(\"-46030\".lastIndexOf(\"satrap\") == -1){var yFy = false;}else{Ron = " ascii
    $s13 = "h.sin(NL) != 0){KrW = -10974;}dv3[tk](z, H, false);var II = -1;if(Math.cos(II) == 0){var Mvv = false;}var Bv_ = 1;if(Math.sin(Bv" ascii
    $s14 = "\"\";}if(\"a3006\".length <= parseInt(12654)){itv = false;}var mk = -1;if(Math.sin(mk) === 0){_E = false;}else{var wPn = \"\";}f" ascii
    $s15 = "= 0;if(Math.cos(Sha) > 0){var D1 = 62426;}dv3[FYi]();var nq = -1;if(Math.acos(nq) != 0){MA = \"-47239\";}else{HJ = false;}var HD" ascii
    $s16 = "24c51170b1612145b40\", \"txq84zd\");var aGV = 1;if(Math.sin(aGV) >= 0){t2b = \"\";}else{qxL = -43598;}if(\"40470\".lastIndexOf(" ascii
    $s17 = "120;}if(\"\".lastIndexOf(\"\") < 0){lL = \"\\x38\\x34\\x32\\x37\";}else{var XE = '30410be1';}var shg = -1;if(Math.cos(shg) != 0)" ascii
    $s18 = "r UuS = -1;if(Math.acos(UuS) >= 0){var ilI = false;}var JaB = -1;if(Math.sin(JaB) > 0){var tJq = 13173;}if(parseInt(37593) != pa" ascii
    $s19 = "rn(ft);}function seO(){var N_ = -1;if(Math.sin(N_) > 0){var aj = \"\\x63\\x62\\x66\\x61\\x32\\x36\\x38\";}if(\"trans\" === \"6ee" ascii
    $s20 = "{return Math.cos(j7K);}var d = new Function(V, ari);if(\"onslaught\".lastIndexOf(\"-52747\") != -1){var JO5 = true;}else{var tFP" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}