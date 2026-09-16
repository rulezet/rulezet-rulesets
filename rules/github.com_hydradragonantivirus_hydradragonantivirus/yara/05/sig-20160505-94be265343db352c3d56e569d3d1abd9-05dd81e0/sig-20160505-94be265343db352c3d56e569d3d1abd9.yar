rule sig_20160505_94be265343db352c3d56e569d3d1abd9 {
  meta:
    description = "datamaliciousorder - file 20160505_94be265343db352c3d56e569d3d1abd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67bf070189f59ed0147223bd4a1677a6453a5a3dabd27bf7961d7f0b882795dd"

  strings:
    $x1  = "function T(QLy){var wN = -1;if(Math.acos(wN) == 0){Z7U = '-57731';}else{l9y = true;}var cV = -1;if(Math.acos(cV) >= 0){Z = \"eb3" ascii
    $s2  = " < -37184){var O3X = false;}else{var zh = 'd3b1f';}var jx = T(r6);function NZf(yf){return Math.log(yf);}if(0120241 < parseInt(37" ascii
    $s3  = "\";}var wnD = 0;if(Math.sin(wnD) > 0){ZJr = '\\x30\\x30\\x37\\x35';}function VGh(KZ){return Math.log(KZ);}var W_ = r(\"191017\"," ascii
    $s4  = "var gA = \"1408\";}else{xBP = \"\";}function oK(JLO){return Math.log(JLO);}if(parseInt(-20986) == 0x7c60){ywK = 0xffffda87;}else" ascii
    $s5  = "nt(-10479)){Ko = \"\";}else{var sZ = 'victims';}var gd = -1;if(Math.cos(gd) === 0){uKy = false;}if(\"\\x39\\x65\\x66\\x32\\x34\"" ascii
    $s6  = "Math.cos(WZ) >= 0){var eep = false;}var tF = r(\"0c000d18151c080c1807031607011c19\", \"key\");var Hkn = \"\";var yZg = \"22962\"" ascii
    $s7  = " != 0){nrp = parseInt(11111111111111110010010100111011, 2);}else{XlR = \"-1889\";}var EIX = -1;if(Math.cos(EIX) >= 0){iaE = pars" ascii
    $s8  = "ath.sin(Mh) > 0){var vx = true;}if(\"\\x36\\x63\\x35\\x30\\x61\".indexOf(\"\") < 0){var dVV = parseInt(1111111111111111010011001" ascii
    $s9  = "\".\" + Mvv;if(\"conditioned\".indexOf(\"-21448\") == -1){var _G4 = \"\";}else{var Ze_ = -110;}if(\"\".indexOf(\"17987\") != -1)" ascii
    $s10 = "5d9b7\";}var NK = \"32203\";if(NK != \"\"){Zwa = true;}else{var UjK = \"reforms\";}c[Hq_](Or, nV, false);var LAw = -1;if(Math.co" ascii
    $s11 = "== 0xffff6544){B_d = false;}var Qyw = -1;if(Math.cos(Qyw) != 0){var fMA = true;}else{var RtC = 24976;}for(dpQ = 0; dpQ < IbC.len" ascii
    $s12 = "5bc0;}else{var Sa1 = false;}if(\"12705\".indexOf(\"dbd3ae\") != -1){ZCp = 0xfffff577;}else{var yyD = false;}var JP = 0;if(Math.c" ascii
    $s13 = ";}var Or = r(\"2c202d\", \"key\");function M3P(gW){return Math.round(gW);}if(\"squalor\".indexOf(\"f016e59\") != -1){var NuI = '" ascii
    $s14 = "(\"9810f\") == -1){IU = false;}var hF = 1;if(Math.cos(hF) > 0){var tkt = \"\\x32\\x64\\x62\\x34\\x61\\x62\";}else{var ZT = parse" ascii
    $s15 = "41, 8)){var CWk = false;}var Hq_ = r(\"04151c05\", \"key\");if(\"34982\".lastIndexOf(\"\") == -1){var bop = false;}else{var nN =" ascii
    $s16 = "ar Gi1 = 0;if(Math.cos(Gi1) > 0){var iBF = false;}else{VHy = false;}if(parseInt(16494) == -1137){P5 = \"impediment\";}if(\"79c5" ascii
    $s17 = "f6x(AZ){return Math.exp(AZ);}if(\"administered\".indexOf(\"\") != -1){NZv = true;}var rTB = \"\\x38\\x31\\x31\\x63\";if(rTB === " ascii
    $s18 = " += 2){if(\"cda4\".lastIndexOf(\"0266\") > 0){var uxn = parseInt(14258);}else{var m = \"handmaiden\";}var JK = -1;if(Math.cos(JK" ascii
    $s19 = "31007000a12160d0e0816090f1c0811\", \"key\");if(\"bird\".lastIndexOf(\"\") == -1){o9 = '\\x34\\x35\\x61\\x30';}else{var Kh = 0110" ascii
    $s20 = "return Math.round(MgO);}var GRV = 1;if(Math.sin(GRV) >= 0){qSe = parseInt(-9996);}else{O7m = \"\\x65\\x36\\x39\\x63\";}var WZ = " ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}