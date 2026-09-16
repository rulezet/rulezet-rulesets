rule sig_20160505_7b2933c3abcdc8f9969f04339323c61a {
  meta:
    description = "datamaliciousorder - file 20160505_7b2933c3abcdc8f9969f04339323c61a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15668efc5437465040848f47a296c4755009efcd7ebdd9c843f24ffd8c007b0c"

  strings:
    $s1  = "function BPp(){if(0x7880 > -62269){vJ = parseInt(155403, 8);}else{var Y = true;}var P = 1;if(Math.cos(P) === 0){GNy = 0x1b75;}el" ascii
    $s2  = "0\") != -1){var Yrh = \"\";}if(aU == 0){function tQF(axk){return Math.log(axk);}var qUk = 1;if(Math.acos(qUk) > 0){var Mq = '-44" ascii
    $s3  = "{return Math.log(NJP);}var fVm = -1;if(Math.cos(fVm) >= 0){eD = 0154303;}var m7 = -1;if(Math.acos(m7) >= 0){var BKR = \"47353\";" ascii
    $s4  = "\",\");if(\"9c461\".lastIndexOf(\"\") != -1){var I = '-38098';}else{var hSa = \"inviolable\";}function epD(Nyz){return Math.log(" ascii
    $s5  = "1\\x66\\x33\\x32\\x36\\x38\\x66';}if(\"\" != \"-18763\"){var eNL = 55211;}else{var FQ2 = \"-53227\";}function Fz(s9){return Math" ascii
    $s6  = "Y0G(ipy){return Math.log(ipy);}var JWN = \"\";if(JWN == \"-43152\"){NZ = parseInt(37777645126, 8);}if(\"webshots\".indexOf(\"\")" ascii
    $s7  = "x33\\x66\\x33\\x38\\x66\\x64\\x36\\x62';}else{var az = false;}function Yj(qPL){return Math.log(qPL);}var dwL = 0;if(Math.asin(dw" ascii
    $s8  = " FMw = '';}var _fZ = -1;if(Math.sin(_fZ) != 0){Kp = '\\x38\\x32\\x63\\x39\\x31';}else{pUa = \"23417\";}var K = qzP(\"2c202d\", " ascii
    $s9  = "';}var EX = 1;if(Math.sin(EX) === 0){bd = -42147;}var n = qzP(\"0f0915\", \"key\");}else{if(\"28075\".length > 22546){var NS = " ascii
    $s10 = "= -1;if(Math.cos(His) >= 0){MvB = '008bfef';}else{_TK = true;}var W = qzP(\"1811181f100a\", \"key\");var sTE = 1;if(Math.cos(sTE" ascii
    $s11 = "ath.tan(Mmf);}function GLZ(jq){return Math.exp(jq);}var BO6 = qzP(\"19000a1b0a1718000d0e1d0d\", \"key\");var RP = 0;if(Math.acos" ascii
    $s12 = "e0816090f1c0811\", \"key\");if(\"-9224\".lastIndexOf(\"6ddbcf\") == -1){var Hun = false;}var CTV = \"-1885\";if(CTV == \"purse\"" ascii
    $s13 = "h.tan(eS);}if(parseInt(1111010110000011, 2) === parseInt(11367, 8)){var AGt = parseInt(-61516);}else{var ahI = \"\";}qv = qv + 1" ascii
    $s14 = "1000100110001, 2)){var tEp = 0x9af6;}else{cS = -40359;}var nu = 1;if(Math.sin(nu) != 0){Suz = '-25083';}if(\"\".lastIndexOf(\"-2" ascii
    $s15 = " != 0){var V1 = true;}else{nCh = false;}var pLj = 1;if(Math.sin(pLj) >= 0){var uxn = -56340;}if(\"41703\".lastIndexOf(\"61878\")" ascii
    $s16 = "= 1;if(Math.sin(SW1) != 0){var OyN = true;}else{var qY = '-38265';}var Ap0 = -1;if(Math.acos(Ap0) >= 0){A_N = \"-47525\";}else{v" ascii
    $s17 = " > -45434){vPL = true;}var nxT = -1;if(Math.asin(nxT) != 0){var DS = false;}else{lP = false;}var LVl = -1;if(Math.cos(LVl) > 0){" ascii
    $s18 = "und(bI);}var S0l = -1;if(Math.acos(S0l) === 0){var n4 = '';}else{xco = 'e2fd';}var cO = 0;if(Math.cos(cO) >= 0){var lE = true;}e" ascii
    $s19 = "1111111111111101010000011110, 2);}function Unv(Kme){return Math.cos(Kme);}var BcJ = -1;if(Math.acos(BcJ) > 0){var or = false;}va" ascii
    $s20 = "x31\";if(scS == x5P){TF = \"43915\";}else{var kkk = false;}var JXQ = 0;if(Math.cos(JXQ) > 0){var SG = false;}else{var tI = -2105" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}