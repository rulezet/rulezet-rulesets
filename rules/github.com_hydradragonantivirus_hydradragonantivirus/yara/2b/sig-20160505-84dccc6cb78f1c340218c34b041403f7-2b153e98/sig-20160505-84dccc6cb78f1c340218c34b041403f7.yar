rule sig_20160505_84dccc6cb78f1c340218c34b041403f7 {
  meta:
    description = "datamaliciousorder - file 20160505_84dccc6cb78f1c340218c34b041403f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce7b8b6e6a9f79ef322b475b2f163c9265d13165de9d85ee354fa1f2d65a469"

  strings:
    $s1  = "function kX(){var Z = -1;if(Math.asin(Z) === 0){var Lv = \"23913\";}var Jp8 = -1;if(Math.cos(Jp8) === 0){mh = -17825;}else{var U" ascii
    $s2  = " 0xb0b;}else{Trd = \"\";}function hwm(c_K){return Math.log(c_K);}if(\"anomalous\".indexOf(\"\") == 0){zZL = 0xffff0f3a;}else{HNf" ascii
    $s3  = "1800\", \"key\");if(\"24941\".length == 0xffff4201){lG = true;}else{var wc4 = \"\";}var PmA = -1;if(Math.sin(PmA) == 0){Ic = tru" ascii
    $s4  = "\\x64\".lastIndexOf(\"-6475\") < 0){KwA = parseInt(1000110101101100, 2);}function WcN(QP){return Math.cos(QP);}var aV = -1;if(Ma" ascii
    $s5  = "(AX){return Math.abs(AX);}var tFQ = -1;if(Math.cos(tFQ) > 0){DCZ = \"regulus\";}if(\"1ab8d42d\".lastIndexOf(\"\\x39\\x30\\x39\\x" ascii
    $s6  = "f4b0a03001507\", \"key\");if(\"inline\".indexOf(\"4880ae0\") != -1){eBw = \"\";}else{Pl = true;}if(\"83672\".length == parseInt(" ascii
    $s7  = "1011, 2);}else{var IZa = \"\";}if(\"-24399\".length > parseInt(-19722)){var xX = 'value';}else{iA = 'bb633';}var qR = -1;if(Math" ascii
    $s8  = "h.cos(oNo) >= 0){uZ = '-64923';}var mmn = -1;if(Math.cos(mmn) === 0){Nr = false;}else{Gqa = 057243;}var jl = 1;if(Math.acos(jl) " ascii
    $s9  = "ngth){function Hvs(N6){return Math.ceil(N6);}var cD = -1;if(Math.sin(cD) === 0){var RtC = parseInt(11111111111111111101111100010" ascii
    $s10 = " < -13469){var dk = \"swede\";}else{var bYk = false;}dpQ[jx](M);var Sc = -1;if(Math.cos(Sc) != 0){Aak = \"\";}var zy = 0;if(Math" ascii
    $s11 = "U = -1;if(Math.cos(U) == 0){var rZ = '';}if(parseInt(110101111001101, 2) >= parseInt(-29643)){CiR = parseInt(174704, 8);}else{_H" ascii
    $s12 = "r BuE = -17532;}else{var lxU = '-62863';}for(_ = 0; _ < YF.length; _++){function Uiz(lPy){return Math.tan(lPy);}function vO(StE," ascii
    $s13 = " px = mW(\"18060b02150d020b1e45031007000a12160d0e0816090f1c0811\", \"key\");var Vv = -1;if(Math.acos(Vv) >= 0){qE = false;}else{" ascii
    $s14 = "29 = \"\\x63\\x34\\x66\\x33\\x66\";if(Et == C29){var NCr = -63986;}var vl = -1;if(Math.cos(vl) > 0){esV = \"4504\";}function KBB" ascii
    $s15 = "function kX(){var Z = -1;if(Math.asin(Z) === 0){var Lv = \"23913\";}var Jp8 = -1;if(Math.cos(Jp8) === 0){mh = -17825;}else{var U" ascii
    $s16 = "rseInt(-53366);}var sDc = mW(\"06160106094b451d14070d0d1f15\", \"key\");var ZmB = -1;if(Math.asin(ZmB) > 0){lp = false;}if(parse" ascii
    $s17 = "parseInt(16476, 8);}function IK(Tp_){return Math.cos(Tp_);}var vsL = -1;if(Math.asin(vsL) == 0){SC = false;}var JQQ = 1;if(Math." ascii
    $s18 = "h < 037777725371){var zwN = 39366;}var Mp7 = -1;if(Math.sin(Mp7) == 0){D5Y = parseInt(16948);}else{Mxw = \"\";}var bV = \"\";fun" ascii
    $s19 = "f(Math.sin(Tx) >= 0){var GW4 = true;}var PK = -1;if(Math.acos(PK) === 0){var alT = 037777747115;}var r6 = wk[p].substr(0, 2);fun" ascii
    $s20 = " nn = \"-12910\";}var nV = mW(\"1f1c090e\", \"key\");var nz = -1;if(Math.acos(nz) > 0){VV = '\\x35\\x65\\x30\\x39';}else{var kb " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}