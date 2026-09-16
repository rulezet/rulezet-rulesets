rule sig_20160321_b03a4538c7cde8b576ece8640c16e07b {
  meta:
    description = "datamaliciousorder - file 20160321_b03a4538c7cde8b576ece8640c16e07b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ee47b3fa9c9393f88d29922a90c7c467c83190e5b19effb5bf619b169e0c44"

  strings:
    $s1  = "return WScript.CreateObject(lejpb);" fullword ascii
    $s2  = "return EvauYUX[0] + EvauYUX[2] + EvauYUX[4] + \".F\" + EvauYUX[7] + EvauYUX[9] + EvauYUX[12] + EvauYUX[14];" fullword ascii
    $s3  = "var Lc = true  , nbiX = wOO[7] + wOO[9] + wOO[11];" fullword ascii
    $s4  = "var wOO = (\"2.XMLHTTP QicvmzG HQWdr XML ream St LhkfAJjC AD GeoHpRi O CiWp D\").split(\" \");" fullword ascii
    $s5  = "var EvauYUX = sTKJK(tFcHMwQDIM+\" \"+\"System GY zdNpK Obj jLLOjP ect CTDOGMw SONaX\", \" \");" fullword ascii
    $s6  = "GubJZ.open(WBtqC,VFTfm,false);" fullword ascii
    $s7  = "function tndlIYscQ(JdVcV) {" fullword ascii
    $s8  = "if (xFxNp > 196880-235){return true;} else {return false;}" fullword ascii
    $s9  = "return SFKWKEV(PI,HBhHv[850-844]+HBhHv[551-544]+HBhHv[539-531]);" fullword ascii
    $s10 = "function feVVQ(fPUUqw) {" fullword ascii
    $s11 = "function SFKWKEV(GiCE,XWKUG) {" fullword ascii
    $s12 = "function FmEW(UNiZH,WEFUZ) {" fullword ascii
    $s13 = "return dtW.split(FTDol);" fullword ascii
    $s14 = "function Lmcw(Kwpnr) {" fullword ascii
    $s15 = "function qirk(CWmeb,XOzLX) {" fullword ascii
    $s16 = "return wHz.size;" fullword ascii
    $s17 = "return fPUUqw.position=656-656;" fullword ascii
    $s18 = "function sTKJK(dtW,FTDol) {" fullword ascii
    $s19 = "function QUQt(bXBjB) {" fullword ascii
    $s20 = "function DEQsEjB(FSBi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}