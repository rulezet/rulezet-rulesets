rule sig_20160311_be96764fec4891b978a4d1d5960566ac {
  meta:
    description = "datamaliciousorder - file 20160311_be96764fec4891b978a4d1d5960566ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d82a917feba279216d94c86d1c0ca58bcc04862e1f524234eb5eccc2c73d732"

  strings:
    $s1  = "return OXYmgmD[0] + OXYmgmD[2] + OXYmgmD[4] + \".F\" + OXYmgmD[7] + OXYmgmD[9] + OXYmgmD[12] + OXYmgmD[14];" fullword ascii
    $s2  = "var Uq = true  , wxpw = Byi[7] + Byi[9] + Byi[11];" fullword ascii
    $s3  = "var OXYmgmD = \"Sc BcwQtOX r jgjFjmprB ipting AHujyUu nmM ile SHAKNpaekDuvEG System ue yiFmB Obj yyBLik ect fkFOlVi\".split(\" " ascii
    $s4  = "tkqxl.open(MrZdk,dxXBW,false);" fullword ascii
    $s5  = "var Byi = (\"2.XMLHTTP MZyTfZn ddvHS XML ream St beWInxan AD uMRTrTS O CShb D\").split(\" \");" fullword ascii
    $s6  = "function LNZe(tGKgR) {" fullword ascii
    $s7  = "function yogf(ugKHo,WSAtv) {" fullword ascii
    $s8  = "return FbBb.ExpandEnvironmentStrings(cjrsb);" fullword ascii
    $s9  = "if (IzLrO > 134898-256){return true;} else {return false;}" fullword ascii
    $s10 = "function Fywv(dXnFM) {" fullword ascii
    $s11 = "function bRSz(cIsbW) {" fullword ascii
    $s12 = "function fUItxsqy(YPqBZ,OVmfza) {" fullword ascii
    $s13 = "function GVWw(xNdER) {" fullword ascii
    $s14 = "function tBzj(HFfIG) {" fullword ascii
    $s15 = "if(l>=z.length) {break;}" fullword ascii
    $s16 = "return kvGDpT.position=961-961;" fullword ascii
    $s17 = "return oGwp.responseBody;" fullword ascii
    $s18 = "return new ActiveXObject(uqVLJL);" fullword ascii
    $s19 = "function ZqzU(ZVDui,QavNt) {" fullword ascii
    $s20 = "if (dXnFM == 1119-919){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}