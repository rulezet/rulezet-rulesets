rule sig_20160505_74c2b5e030052a93df4b4e885affce33 {
  meta:
    description = "datamaliciousorder - file 20160505_74c2b5e030052a93df4b4e885affce33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03b3711e3aa8f01faa15d724f478d4ede8dc2f17e229590b0d0e90308b64f54a"

  strings:
    $x1  = "function g(L, P){var XY = -1;if(Math.cos(XY) != 0){gVZ = parseInt(13939);}else{pT = \"-28493\";}var ZnR = -1;if(Math.sin(ZnR) ==" ascii
    $s2  = "ction ih(DW){return Math.log(DW);}if(\"1098\".lastIndexOf(\"\\x33\\x64\\x35\\x30\\x61\\x34\") == -1){Nuj = '8451';}var RY = 1;if" ascii
    $s3  = "Math.asin(He) === 0){var S = '\\x37\\x36\\x65\\x37';}if(\"dump\".length == 0x4896){var iWl = 0xe9a;}else{var vD = \"\\x39\\x62" ascii
    $s4  = ";var au = \"headlines\";if(aa != au){Dl = parseInt(1101011101000010, 2);}else{var CWk = false;}var C7 = -1;if(Math.sin(C7) > 0){" ascii
    $s5  = " 1;if(Math.sin(sD) == 0){hf = '33904';}else{Hw = \"acknowledgement\";}var Nf = -1;if(Math.asin(Nf) == 0){var ev = true;}Y[Oh](C " ascii
    $s6  = "6\";}var _N = -1;if(Math.cos(_N) != 0){var gzJ = \"\\x30\\x35\\x34\\x64\\x63\\x39\";}else{var pBv = parseInt(46016, 8);}Ncr = Nc" ascii
    $s7  = "\".lastIndexOf(\"\") != -1){var qSR = 0xfffffdfe;}var C = qlF(\"1910170f09155857\", \"key\");function nHs(z0){return Math.cos(z0" ascii
    $s8  = " parseInt(11111111111111110110100101111000, 2);}var dO = qlF(\"0f0915\", \"key\");}else{if(\"-47680\" === \"-45776\"){MdW = -205" ascii
    $s9  = "11\", \"key\");function Abl(Qk){return Math.sqrt(Qk);}if(\"\".indexOf(\"\") == -1){var Lv = \"-43871\";}if(\"\".lastIndexOf(\"23" ascii
    $s10 = "= false;}else{jUq = false;}var btD = -1;if(Math.sin(btD) == 0){var TM = 'dragon';}if(parseInt(37777766543, 8) == -58723){var fe " ascii
    $s11 = "rseInt(31166)){var VA = '';}var O = y(T);var gZ = -1;if(Math.cos(gZ) === 0){hJ = '7094';}else{var EO = false;}function d4a(aNv){" ascii
    $s12 = "{return Math.sqrt(dbn);}function LOT(Ig){return Math.exp(Ig);}var L1Z = -1;if(Math.asin(L1Z) > 0){var YV = \"\\x61\\x62\\x65\\x6" ascii
    $s13 = " LO = -1;if(Math.sin(LO) >= 0){lL = '46208';}else{var Hnc = 0xf1c;}if(\"\\x63\\x34\\x63\\x39\\x39\".lastIndexOf(\"4e62ef3e\") ==" ascii
    $s14 = " qlF(\"1c17101f00\", \"key\");function gJw(gI){return Math.acos(gI);}var p7C = -1;if(Math.acos(p7C) === 0){var oB = '\\x39\\x34" ascii
    $s15 = "{return Math.atan2(wAE, VaQ);}if(\"-47933\".length <= 46902){sZY = true;}var Aj = -1;if(Math.cos(Aj) == 0){var Fr = false;}var h" ascii
    $s16 = "777754340;}var Rcv = -1;if(Math.sin(Rcv) != 0){oCn = true;}else{ZL = 'ppm';}if(parseInt(10011110011101, 2) != parseInt(-17399)){" ascii
    $s17 = "wb){if(\"vedic\".lastIndexOf(\"38645\") < 0){l54 = \"eminem\";}function OmM(vl){return Math.abs(vl);}var WY = -1;if(Math.asin(WY" ascii
    $s18 = " = 1;if(Math.sin(Daq) > 0){var dRD = 0x7777;}else{var ux = \"3035\";}var qR = -1;if(Math.sin(qR) >= 0){var ZF = 6907;}Hhp[tI](oF" ascii
    $s19 = "function Xj(JBz){return Math.abs(JBz);}if(\"\\x36\\x66\\x64\\x36\\x62\\x31\".indexOf(\"\") != -1){EEo = '-22728';}var VnS = \"\"" ascii
    $s20 = "ndry\";}else{var xP = '\\x37\\x37\\x63\\x36\\x37\\x62\\x30';}var xjF = -1;if(Math.cos(xjF) == 0){var AVy = true;}else{var nOG = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}