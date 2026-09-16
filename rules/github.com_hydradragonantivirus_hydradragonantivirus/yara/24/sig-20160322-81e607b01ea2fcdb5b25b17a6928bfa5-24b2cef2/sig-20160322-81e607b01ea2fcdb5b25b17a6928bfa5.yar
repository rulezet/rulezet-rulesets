rule sig_20160322_81e607b01ea2fcdb5b25b17a6928bfa5 {
  meta:
    description = "datamaliciousorder - file 20160322_81e607b01ea2fcdb5b25b17a6928bfa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1fb5db765da70ca28881fbd271b576b1b16e2d1b32984196de1827ea2fd9b3a"

  strings:
    $s1  = "return WScript.CreateObject(JnnDE);" fullword ascii
    $s2  = "return hZSSnUN[0] + hZSSnUN[2] + hZSSnUN[4] + \".F\" + hZSSnUN[7] + hZSSnUN[9] + hZSSnUN[12] + hZSSnUN[14];" fullword ascii
    $s3  = "var UL = true  , rwak = iIi[7] + iIi[9] + iIi[11];" fullword ascii
    $s4  = "var iIi = (\"2.XMLHTTP SghqzrV PmsQW XML ream St YGSumwap AD dZerPIm O FCop D\").split(\" \");" fullword ascii
    $s5  = "IXoL.open(wtAzi,EMMjz,false);" fullword ascii
    $s6  = "var hZSSnUN = wnXlS(HuVXPoqHbr+\" \"+\"System wK jEAcP Obj ZaWvzi ect jkUhdYO YRtjs\", \" \");" fullword ascii
    $s7  = "function xdcT(FQChS) {" fullword ascii
    $s8  = "function OtdokLH(MPBb,HCbnT) {" fullword ascii
    $s9  = "function FNPp(mCuAC) {" fullword ascii
    $s10 = "MkD = F; break; " fullword ascii
    $s11 = "function VvXGUdtk(pwQK) {" fullword ascii
    $s12 = "function tIuPoQrAV(cPQmF) {" fullword ascii
    $s13 = "if (q >= YmutP.length) {break;}" fullword ascii
    $s14 = "return xql.split(okAXZ);" fullword ascii
    $s15 = "return MPBb.ExpandEnvironmentStrings(HCbnT);" fullword ascii
    $s16 = "function XLsdy(pyefez) {" fullword ascii
    $s17 = "return FIN.size;" fullword ascii
    $s18 = "if (ONNzV == 305-105){return true;} else {return false;}" fullword ascii
    $s19 = "function RgIH(ILHLj,JnDtv) {" fullword ascii
    $s20 = "function yWsb(ONNzV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}