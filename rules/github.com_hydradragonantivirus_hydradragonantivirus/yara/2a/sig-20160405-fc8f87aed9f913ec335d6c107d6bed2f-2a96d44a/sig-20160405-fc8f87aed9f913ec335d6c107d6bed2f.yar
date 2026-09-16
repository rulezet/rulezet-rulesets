rule sig_20160405_fc8f87aed9f913ec335d6c107d6bed2f {
  meta:
    description = "datamaliciousorder - file 20160405_fc8f87aed9f913ec335d6c107d6bed2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4f00d46ed66b129b7392c0e15cf130ad3c2b19a597e05940906e003f14ef98"

  strings:
    $s1  = "function eYEJLCWEP(iJbJPdtPoau) {" fullword ascii
    $s2  = "var Wh = true  , gNCx = WLz[7] + WLz[9] + WLz[11];" fullword ascii
    $s3  = "return ztutIGg[0] + ztutIGg[2] + ztutIGg[4] + \".F\" + ztutIGg[7] + ztutIGg[9] + ztutIGg[12] + ztutIGg[14];" fullword ascii
    $s4  = "var WLz = (\"2.XMLHTTP ErICdRp oZcmc XML ream St HcZVDDDC AD AUmnmUs O Auft D\").split(\" \");" fullword ascii
    $s5  = "RNAa.open(hBZvi,uhLcJ,false);" fullword ascii
    $s6  = "if(R>=D.length) {break;}" fullword ascii
    $s7  = "return sOISngB[0];" fullword ascii
    $s8  = "function QDUFRVV(UwLV) {" fullword ascii
    $s9  = "function dIzaC(JoveNB) {" fullword ascii
    $s10 = "function NoXg(YTCNZ,uhLcJ,hBZvi) {" fullword ascii
    $s11 = "function hFJrGFQd(gLBj) {" fullword ascii
    $s12 = "function DLOA(OLYOK) {" fullword ascii
    $s13 = "function DbUkPx(cxgq,sveeTe) {" fullword ascii
    $s14 = "if (WnHGe == 681-481){return true;} else {return false;}" fullword ascii
    $s15 = "var FmssTIY = \"NFMbCX*NUv*pt.S\"+\"hell*OWlirsO*Scri*\";" fullword ascii
    $s16 = "function wZOFw(RIkQiw) {" fullword ascii
    $s17 = "function RXUf(XQfZt) {" fullword ascii
    $s18 = "return IXAA;" fullword ascii
    $s19 = "function aOWoWS(TwzWTxu) {" fullword ascii
    $s20 = "if (K >= KXmXB.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}