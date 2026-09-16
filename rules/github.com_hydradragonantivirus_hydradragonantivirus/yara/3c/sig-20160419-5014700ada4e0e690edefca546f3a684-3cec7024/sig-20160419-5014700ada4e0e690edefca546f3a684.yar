rule sig_20160419_5014700ada4e0e690edefca546f3a684 {
  meta:
    description = "datamaliciousorder - file 20160419_5014700ada4e0e690edefca546f3a684.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d844e4f8d74e8091490193635b74f9ad3bbbc65cf3fff250bbca738c887d8561"

  strings:
    $s1  = "var IH = true  , Tbiy = jJU[7] + jJU[9] + jJU[11];" fullword ascii
    $s2  = "return CHmwuaQ[0] + CHmwuaQ[2] + CHmwuaQ[4] + \".F\" + CHmwuaQ[7] + CHmwuaQ[9] + CHmwuaQ[12] + CHmwuaQ[14];" fullword ascii
    $s3  = "var jJU = (\"2.XMLHTTP JdMiiKS zABrJ XML ream St SqHcGsVe AD gKukdRj O MmPK D\").split(\" \");" fullword ascii
    $s4  = "SWSG.open(kXJKR,XXbJy,false);" fullword ascii
    $s5  = "function zgec(UVrOr) {" fullword ascii
    $s6  = "return vFYoJ.status;" fullword ascii
    $s7  = "return zeZQtqI;" fullword ascii
    $s8  = "return mmGP[RjWnoyf[0]+RjWnoyf[1]];" fullword ascii
    $s9  = "function HGttq(hFgjSN) {" fullword ascii
    $s10 = "function jQFg(HmopA) {" fullword ascii
    $s11 = "return tCZhVJy(an,xnfRde+KmBMf[612-604]);" fullword ascii
    $s12 = "function HEAW(oncPZ,kkRmP) {" fullword ascii
    $s13 = "function MHRcW(QOMKtQta,INui) {" fullword ascii
    $s14 = "function IoaGfdpL(CbnE) {" fullword ascii
    $s15 = "ktE = D; break; " fullword ascii
    $s16 = "return xbNPDtG[0];" fullword ascii
    $s17 = "if (RoXUM > 156667-331){return true;} else {return false;}" fullword ascii
    $s18 = "if(D>=X.length) {break;}" fullword ascii
    $s19 = "function rxkNhGaFE(NUtGneaDVKQ) {" fullword ascii
    $s20 = "return new ActiveXObject(IKCo);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}