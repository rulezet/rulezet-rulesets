rule sig_20160506_e11eb9989795de6f46502248aee1038e {
  meta:
    description = "datamaliciousorder - file 20160506_e11eb9989795de6f46502248aee1038e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1786c06272801fd2d0787d2ee56b4c9c0e1d40e78edc8f1475e835d7cd08ebcd"

  strings:
    $x1  = "function e(){if(\"32418\".lastIndexOf(\"a3a3e8\") == 0){R_i = 'van';}var BcJ = -1;if(Math.cos(BcJ) > 0){var _q = \"-45386\";}var" ascii
    $s2  = "x31\\x39\\x63\";}function uu(gR){return Math.log(gR);}var DJ = Math.floor(Math.random() * 65536);function cYe(io){return Math.ex" ascii
    $s3  = "{return Math.log(gJq);}return(CpE);}f();" fullword ascii
    $s4  = "th.log(wZ);}if(\"\\x34\\x63\\x31\\x66\".indexOf(\"\") < 0){jRa = parseInt(62267);}else{DM8 = \"aspiration\";}var flg = 1;if(Math" ascii
    $s5  = "r aWw = '\\x65\\x36\\x36\\x31\\x64\\x37\\x32\\x66';}else{var gX = false;}a8m[CcW] = 1;if(\"attempting\".length >= -8516){var NS " ascii
    $s6  = "{yi = true;}var Bol = 0;if(Math.cos(Bol) === 0){var ilX = '-9542';}else{var fDD = true;}var fTz = \"contemporaneous\";if(fTz != " ascii
    $s7  = "12841 == parseInt(9492)){var jm = 49022;}else{var INF = '22230';}var lf = 0;if(Math.acos(lf) != 0){lv2 = -51335;}else{KK = \"fuc" ascii
    $s8  = "e{var IPt = 'postpone';}if(52449 === -3217){Gqa = -1005;}var AMi = 0;if(Math.asin(AMi) >= 0){P9 = 'gel';}else{rJ = \"97166e\";}v" ascii
    $s9  = "\\x32\\x32\\x39\";}var _uL = -1;if(Math.sin(_uL) > 0){tvG = false;}var ycE = \"\";var bJC = -1;if(Math.asin(bJC) == 0){var Ano =" ascii
    $s10 = "2105;}else{var yXq = '10262';}try{Lw = false;}catch(mC){var bfD = \"23671\";}function n2J(fW){return Math.log(fW);}if(\"firework" ascii
    $s11 = "= 0){IrC = \"-27183\";}else{Aak = \"-30755\";}var Q5x = Q5x.split(\",\");var tcu = 1;if(Math.sin(tcu) >= 0){F6O = \"\\x38\\x65" ascii
    $s12 = "th.sqrt(Qh);}var Kk_ = -1;if(Math.asin(Kk_) >= 0){var MA = '34948';}else{var r1g = \"70625b0\";}var D5 = 0;if(Math.sin(D5) > 0){" ascii
    $s13 = "r(HrN);}var ht = -1;if(Math.cos(ht) != 0){jxm = \"co\";}if(parseInt(-29112) < 27371){VV = '';}else{var kb = 18450;}try{var TyO =" ascii
    $s14 = "rn(oFn);}function Rk(QLy, As){var Yf = -1;if(Math.asin(Yf) != 0){var _T = 38060;}var JD = 0;if(Math.sin(JD) > 0){kxN = true;}if(" ascii
    $s15 = "exOf(\"56678\") == -1){ih = parseInt(34553);}var DpY = -1;if(Math.cos(DpY) == 0){var ny = '';}else{zuP = '9a8f00';}function Fr2(" ascii
    $s16 = "(Math.sin(si) != 0){var rC = parseInt(-27023);}else{bq = -955;}function XLj(ag9){return Math.round(ag9);}var I = parseInt(B[2]);" ascii
    $s17 = "D = -1;if(Math.asin(wXD) > 0){var GTJ = parseInt(11021);}else{eBV = -60817;}var RJ = 1;if(Math.sin(RJ) != 0){var at = true;}else" ascii
    $s18 = " 0){Lc = \"\\x65\\x37\\x62\\x62\\x32\";}else{var NJz = 'if';}var KoV = QX + \"\\\\\" + DJ + \".\" + DzC;function NyK(FHm){return" ascii
    $s19 = "rue;}var U8V = -1;if(Math.cos(U8V) == 0){var iY = true;}if(0x61a6 <= 037777647450){var hy = \"12394\";}else{HC = 0xffffebc4;}fun" ascii
    $s20 = "function e(){if(\"32418\".lastIndexOf(\"a3a3e8\") == 0){R_i = 'van';}var BcJ = -1;if(Math.cos(BcJ) > 0){var _q = \"-45386\";}var" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}