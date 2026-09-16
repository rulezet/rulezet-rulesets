rule sig_20160404_c2460ee2881265e8aa422fc40b3162c1 {
  meta:
    description = "datamaliciousorder - file 20160404_c2460ee2881265e8aa422fc40b3162c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7821eb815d967bcf0b4e789c05274e41c158150d25eeaafbf3a03d345b9b7723"

  strings:
    $s1  = "return apwyUzg[0] + apwyUzg[2] + apwyUzg[4] + \".F\" + apwyUzg[7] + apwyUzg[9] + apwyUzg[12] + apwyUzg[14];" fullword ascii
    $s2  = "var Cn = true  , cPsD = Huh[7] + Huh[9] + Huh[11];" fullword ascii
    $s3  = "var apwyUzg = GfLmw(zOSTwxUDET+\" \"+\"System ld xJUVY Obj tlXiVs ect mLYpVay MBkWI\", \" \");" fullword ascii
    $s4  = "var Huh = (\"2.XMLHTTP gAoJrfW CvrMt XML ream St iyahxhLS AD XFNqeGw O yiyw D\").split(\" \");" fullword ascii
    $s5  = "function DwBS(tGUbF) {" fullword ascii
    $s6  = "if (J >= YUnhV.length) {break;}" fullword ascii
    $s7  = "function pAUC(oilpq,djWLe) {" fullword ascii
    $s8  = "function UXxK(GEXAd) {" fullword ascii
    $s9  = "return DUWgn.status;" fullword ascii
    $s10 = "function juLKZG(eoyJmRX) {" fullword ascii
    $s11 = "function vQKl(lNcby) {" fullword ascii
    $s12 = "return Usclflu(hj,yScTp[537-531]+yScTp[590-583]+yScTp[436-428]);" fullword ascii
    $s13 = "function dLUV(YUnhV) {" fullword ascii
    $s14 = "function rrSL(DUWgn) {" fullword ascii
    $s15 = "var MyYsXhJ = \"gSYQWM*Ysi*pt.S\"+\"hell*GSqeIZr*Scri*\";" fullword ascii
    $s16 = "if (lNcby > 161730-832){return true;} else {return false;}" fullword ascii
    $s17 = "return zJXDiJL;" fullword ascii
    $s18 = "return uqxEiWi;" fullword ascii
    $s19 = "function NPIS(oBhcl,oVvTz) {" fullword ascii
    $s20 = "function OqxEPYyrU(rDgsk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}