rule sig_20160315_e4c8b23d984e059da7293a201c098cdb {
  meta:
    description = "datamaliciousorder - file 20160315_e4c8b23d984e059da7293a201c098cdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6595742c110ffda9e407f0ddc2ee3b2556b6c5547ff077cb931908590e2b357d"

  strings:
    $s1  = "var SK = true  , AFRL = UtG[7] + UtG[9] + UtG[11];" fullword ascii
    $s2  = "return WWQevNT[0] + WWQevNT[2] + WWQevNT[4] + \".F\" + WWQevNT[7] + WWQevNT[9] + WWQevNT[12] + WWQevNT[14];" fullword ascii
    $s3  = "var WWQevNT = CKrxS(\"Sc QDtbuXa r mlhSsbSmD ipting mAElFlV wQa ile esEezswaekhZjt System dR uPYFU Obj WUelFH ect zdIsWix KYQBj" ascii
    $s4  = "tzIfc.open(XZLhh,eRxaF,false);" fullword ascii
    $s5  = "var UtG = (\"2.XMLHTTP syNoyzp lrSJP XML ream St GhLQXZKZ AD ERetRcD O ZEjU D\").split(\" \");" fullword ascii
    $s6  = "var WWQevNT = CKrxS(\"Sc QDtbuXa r mlhSsbSmD ipting mAElFlV wQa ile esEezswaekhZjt System dR uPYFU Obj WUelFH ect zdIsWix KYQBj" ascii
    $s7  = "if(Q>=D.length) {break;}" fullword ascii
    $s8  = "return IZyissZ(xk,edcnN[187-181]+edcnN[262-255]+edcnN[941-933]);" fullword ascii
    $s9  = "function GtLfmPo(Rtbe) {" fullword ascii
    $s10 = "function pPBgX(kMmNEt) {" fullword ascii
    $s11 = "return TBdEmvT" fullword ascii
    $s12 = "if (Eelqm == 732-532){return true;} else {return false;}" fullword ascii
    $s13 = "return sqkd.ExpandEnvironmentStrings(egCJF);" fullword ascii
    $s14 = "return new ActiveXObject(kMmNEt);" fullword ascii
    $s15 = "function leCQZ(icZGoe) {" fullword ascii
    $s16 = "return egD.size;" fullword ascii
    $s17 = "function RzgdBswE(egD) {" fullword ascii
    $s18 = "function sGex(asAlY) {" fullword ascii
    $s19 = "function thIQfddTf(HlXEc) {" fullword ascii
    $s20 = "function hRRM(yjcEB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}