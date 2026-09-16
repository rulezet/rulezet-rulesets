rule sig_20160506_132c4e8db7439a5732a163247411476e {
  meta:
    description = "datamaliciousorder - file 20160506_132c4e8db7439a5732a163247411476e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1483685b7d9510049fb08fa2bdbc1df886f67a3f0004832b1ecf2fcfef125c6"

  strings:
    $s1  = "function cZT(g){function iu(wBT){return Math.log(wBT);}if(\"42fe880\".lastIndexOf(\"\") < 0){var MC = 56977;}else{var Ite = '\\x" ascii
    $s2  = "ion MZ(HrN){return Math.log(HrN);}if(\"3dad4a\".length === parseInt(-43912)){var hwC = false;}var W = r + \"\\\\\" + O_ + \".\" " ascii
    $s3  = "e{var BuT = \"\";}var aT = -1;if(Math.sin(aT) != 0){var uT = \"\";}function sE(Ub){return Math.log(Ub);}function rI(BJN){return " ascii
    $s4  = "ath.ceil(ELb);}function Ax(Wf){return Math.log(Wf);}var KW = \"28321\";if(KW != \"\"){wS = true;}var _M = 1;if(Math.acos(_M) >= " ascii
    $s5  = "function cZT(g){function iu(wBT){return Math.log(wBT);}if(\"42fe880\".lastIndexOf(\"\") < 0){var MC = 56977;}else{var Ite = '\\x" ascii
    $s6  = "g = \"\";var To = \"b7846\";if(Mg != To){ON = 'fears';}if(\"\".indexOf(\"blockhead\") == -1){var Imw = false;}else{var IU = '\\x" ascii
    $s7  = "3p = \"terminology\";}if(62593 <= 51808){var pW = true;}else{cHt = true;}if(\"-5081\".indexOf(\"44425\") == -1){vmZ = false;}els" ascii
    $s8  = " \"\\x66\\x34\\x62\\x61\\x35\\x32\";}function n4(u9j){return Math.log(u9j);}E_[mh] = 1;}}}catch(SN){if(\"\\x39\\x34\\x37\\x37\\x" ascii
    $s9  = "2\\x32\\x33\\x31\\x36';}if(parseInt(14105) === parseInt(-42547)){var Bh = -24563;}else{EU = false;}V = V + 1;function IL(Lg_){re" ascii
    $s10 = "r _o = 1;if(Math.sin(_o) == 0){Zu8 = true;}if(\"\".indexOf(\"\") != -1){var KSn = \"-5710\";}var PZ = \"\";if(PZ === \"\\x66\\x6" ascii
    $s11 = "53 <= 27918){Hx = \"\";}else{sq = \"\";}var iTk = -1;if(Math.cos(iTk) != 0){A_N = 9533;}var hw_ = 0;if(Math.cos(hw_) === 0){var " ascii
    $s12 = "ar WX = 1;if(Math.cos(WX) >= 0){ZVX = \"\\x64\\x64\\x33\\x34\\x62\";}var GoF = -1;if(Math.sin(GoF) != 0){var DW = \"\";}else{var" ascii
    $s13 = "62\\x30\\x38\\x34\\x31\\x38\"){SAa = \"\";}else{zQX = true;}var EQ = -1;if(Math.acos(EQ) == 0){var lNy = false;}var Udi = -1;if(" ascii
    $s14 = "f(\"b83befc\") != -1){var _C = '';}if(0106112 < 0x3b03){Ko = \"22930\";}var sph = 1;if(Math.sin(sph) === 0){rY = \"54695\";}else" ascii
    $s15 = "M(ajo){return Math.tan(ajo);}var rlZ = 0;if(Math.cos(rlZ) != 0){var Ze_ = -54790;}for(lUp = 0; lUp < Fl.length; lUp++){var J5O =" ascii
    $s16 = "48760){IXs = \"9ba86c29\";}var mh = y[1];var zS = -1;if(Math.sin(zS) != 0){var SJ = true;}else{_e = false;}if(\"-58963\".indexOf" ascii
    $s17 = "x39\\x30\";}else{var _m = 'foal';}var DBl = 1;if(Math.sin(DBl) == 0){Erf = -58835;}else{xu = '\\x61\\x64\\x38\\x34\\x61\\x30';}v" ascii
    $s18 = "';}var wy = 1;if(Math.acos(wy) > 0){FMw = 0xffffbef1;}var eep = -1;if(Math.cos(eep) === 0){var cPQ = 0xffffcddf;}else{var TYf = " ascii
    $s19 = "5\\x30\\x32\\x35\\x39\\x31\\x61';}if(\"0012\".indexOf(\"\") != -1){var hh = parseInt(100767, 8);}function T(lW1){return Math.abs" ascii
    $s20 = "rn Math.ceil(ibv);}var EhK = -1;if(Math.cos(EhK) === 0){var b4 = 0x5d34;}function a_r(uLq){return Math.ceil(uLq);}if(0xffffed89 " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}