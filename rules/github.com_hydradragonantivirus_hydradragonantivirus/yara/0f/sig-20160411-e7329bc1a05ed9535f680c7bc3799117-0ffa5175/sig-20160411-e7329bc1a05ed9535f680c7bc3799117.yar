rule sig_20160411_e7329bc1a05ed9535f680c7bc3799117 {
  meta:
    description = "datamaliciousorder - file 20160411_e7329bc1a05ed9535f680c7bc3799117.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f969abe8bf21def88303c32873c657e91b309292d87c83806a600ec687192a4e"

  strings:
    $s1  = "function UAopnYv(MvkF,SUEYe) {" fullword ascii
    $s2  = "var RY = true  , BsCc = YtF[7] + YtF[9] + YtF[11];" fullword ascii
    $s3  = "return BylcmiY[0] + BylcmiY[2] + BylcmiY[4] + \".F\" + BylcmiY[7] + BylcmiY[9] + BylcmiY[12] + BylcmiY[14];" fullword ascii
    $s4  = "var YtF = (\"2.XMLHTTP KhVfWOn DthwZ XML ream St WYBQLhBw AD UxYyPni O VCHK D\").split(\" \");" fullword ascii
    $s5  = "ffjG.open(OdlRV,ZVaPa,false);" fullword ascii
    $s6  = "if(Q>=c.length) {break;}" fullword ascii
    $s7  = "return sxU[CDrf[0]](kmeQR);" fullword ascii
    $s8  = "function mUfuFB(mElN,OtEBJQ) {" fullword ascii
    $s9  = "return UAopnYv(dV,lBjabl+XBBfg[897-889]);" fullword ascii
    $s10 = "return spUNlU[mTiE[214-214]]=719-719;" fullword ascii
    $s11 = "return new ActiveXObject(LBEx);" fullword ascii
    $s12 = "function DGmADQ(ooEXJAd) {" fullword ascii
    $s13 = "function ryRB(kPlRD,hVnCt) {" fullword ascii
    $s14 = "function ndlc(eCpBn) {" fullword ascii
    $s15 = "function RgMj(EMOHq) {" fullword ascii
    $s16 = "function grtAZ(oUvJTgka,iqKy) {" fullword ascii
    $s17 = "if (O >= eCpBn.length) {break;}" fullword ascii
    $s18 = "function TwXU(JtbYR) {" fullword ascii
    $s19 = "return ZFfRO.status;" fullword ascii
    $s20 = "function jGsFo(spUNlU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}