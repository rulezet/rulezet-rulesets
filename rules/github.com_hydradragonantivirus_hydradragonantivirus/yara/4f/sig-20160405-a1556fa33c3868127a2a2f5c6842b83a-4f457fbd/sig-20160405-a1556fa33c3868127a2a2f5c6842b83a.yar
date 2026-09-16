rule sig_20160405_a1556fa33c3868127a2a2f5c6842b83a {
  meta:
    description = "datamaliciousorder - file 20160405_a1556fa33c3868127a2a2f5c6842b83a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06350c6ddbd3c56ffe64a417c6cb45acbb826c59d597eac9dc95e1fa6f995719"

  strings:
    $s1  = "var KM = true  , mHpo = mdG[7] + mdG[9] + mdG[11];" fullword ascii
    $s2  = "return FnsvaYe[0] + FnsvaYe[2] + FnsvaYe[4] + \".F\" + FnsvaYe[7] + FnsvaYe[9] + FnsvaYe[12] + FnsvaYe[14];" fullword ascii
    $s3  = "var mdG = (\"2.XMLHTTP QQWpmgl NZbBA XML ream St FmfkmrAE AD QtHDHnb O jQvw D\").split(\" \");" fullword ascii
    $s4  = "dXyx.open(AyxIO,xwuNt,false);" fullword ascii
    $s5  = "function TXTR(GhCom,xwuNt,AyxIO) {" fullword ascii
    $s6  = "return Pspif.status;" fullword ascii
    $s7  = "function QxdXKGN(Yene,oXWtD) {" fullword ascii
    $s8  = "function LWxc(sTtbd) {" fullword ascii
    $s9  = "return mslMiDY[0];" fullword ascii
    $s10 = "function UqDR(AgMep,NeIrk) {" fullword ascii
    $s11 = "function Pllq(Pspif) {" fullword ascii
    $s12 = "function eXzw(KAUVc,HvkRD) {" fullword ascii
    $s13 = "return XGk.size;" fullword ascii
    $s14 = "function HkEHrBTzc(GrIwi) {" fullword ascii
    $s15 = "return ogjae;" fullword ascii
    $s16 = "function icGcBEO(TklM) {" fullword ascii
    $s17 = "function vdjX(BIRNp) {" fullword ascii
    $s18 = "if (o >= kbxbB.length) {break;}" fullword ascii
    $s19 = "return uDev;" fullword ascii
    $s20 = "function bcEEa(VTaMqq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}