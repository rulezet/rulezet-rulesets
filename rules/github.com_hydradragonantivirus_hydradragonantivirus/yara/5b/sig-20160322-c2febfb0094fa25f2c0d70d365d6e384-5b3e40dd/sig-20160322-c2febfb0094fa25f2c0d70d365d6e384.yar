rule sig_20160322_c2febfb0094fa25f2c0d70d365d6e384 {
  meta:
    description = "datamaliciousorder - file 20160322_c2febfb0094fa25f2c0d70d365d6e384.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2409fa77245410f51c965cb13fcf837c2a8931baf73a43aa59396274431b69d"

  strings:
    $s1  = "return WScript.CreateObject(zjfSd);" fullword ascii
    $s2  = "return rJQkrOs[0] + rJQkrOs[2] + rJQkrOs[4] + \".F\" + rJQkrOs[7] + rJQkrOs[9] + rJQkrOs[12] + rJQkrOs[14];" fullword ascii
    $s3  = "var sE = true  , Uwup = Mlx[7] + Mlx[9] + Mlx[11];" fullword ascii
    $s4  = "dkni.open(MsnsL,wjafk,false);" fullword ascii
    $s5  = "var rJQkrOs = bNyaB(YydoiOBUav+\" \"+\"System IY dqKwu Obj fxSZWe ect pDNuSQT GWTyX\", \" \");" fullword ascii
    $s6  = "var Mlx = (\"2.XMLHTTP kOYdccI cfaET XML ream St YoCFmbCb AD LdRjHbl O NPsy D\").split(\" \");" fullword ascii
    $s7  = "function bNyaB(zcw,laFqj) {" fullword ascii
    $s8  = "return zYQcPuL(Gh,fvGIU[364-358]+fvGIU[580-573]+fvGIU[607-599]);" fullword ascii
    $s9  = "if (RtZhp == 1125-925){return true;} else {return false;}" fullword ascii
    $s10 = "function Nzzf(zjfSd) {" fullword ascii
    $s11 = "function TyAg(RtZhp) {" fullword ascii
    $s12 = "function qLLNfpFZI(thjvdjJcZBN) {" fullword ascii
    $s13 = "function gLbBf(sJajzt) {" fullword ascii
    $s14 = "function imETlyKf(cZCZ) {" fullword ascii
    $s15 = "function xIGStESo(fsL) {" fullword ascii
    $s16 = "function AFYQ(TTnZE,wjafk,MsnsL) {" fullword ascii
    $s17 = "function UypX(zoKKw) {" fullword ascii
    $s18 = "function zYQcPuL(MzhN,DNkIG) {" fullword ascii
    $s19 = "function yzOO(hjqOx) {" fullword ascii
    $s20 = "return sJajzt.position=510-510;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}