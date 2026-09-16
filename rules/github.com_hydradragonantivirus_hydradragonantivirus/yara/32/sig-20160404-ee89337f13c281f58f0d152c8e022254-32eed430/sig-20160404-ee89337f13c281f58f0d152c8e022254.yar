rule sig_20160404_ee89337f13c281f58f0d152c8e022254 {
  meta:
    description = "datamaliciousorder - file 20160404_ee89337f13c281f58f0d152c8e022254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22d1bd7e47902472c53d900d5d7e6a528adbcecc870ad58c656170dfe984ca9c"

  strings:
    $s1  = "return UIGlAAD[0] + UIGlAAD[2] + UIGlAAD[4] + \".F\" + UIGlAAD[7] + UIGlAAD[9] + UIGlAAD[12] + UIGlAAD[14];" fullword ascii
    $s2  = "var nI = true  , UhKt = WkO[7] + WkO[9] + WkO[11];" fullword ascii
    $s3  = "var UIGlAAD = gCdqX(bItRVWvelo+\" \"+\"System WV LcfCI Obj RzuIBF ect bhSwAvZ QRwMX\", \" \");" fullword ascii
    $s4  = "var WkO = (\"2.XMLHTTP mNnUjqG WMziH XML ream St palPxQFB AD LkpOkEr O kXde D\").split(\" \");" fullword ascii
    $s5  = "kcVc.open(EIjxH,ZNlMA,false);" fullword ascii
    $s6  = "if(H>=v.length) {break;}" fullword ascii
    $s7  = "function EgbPx(HlIxAn) {" fullword ascii
    $s8  = "function OIuBuSt(onuJ,CZbaT) {" fullword ascii
    $s9  = "return kIBn[HpDEfi[0]];" fullword ascii
    $s10 = "return OIuBuSt(sV,TiRNM[625-619]+TiRNM[292-285]+TiRNM[291-283]);" fullword ascii
    $s11 = "return zgAns;" fullword ascii
    $s12 = "return xMk.size;" fullword ascii
    $s13 = "function uGud(XKZzP) {" fullword ascii
    $s14 = "function yZpY(VriyE) {" fullword ascii
    $s15 = "function qkDJBDVsn(tETeV) {" fullword ascii
    $s16 = "function aDmiBBev(yNJI) {" fullword ascii
    $s17 = "if (ZuWYw == 890-690){return true;} else {return false;}" fullword ascii
    $s18 = "function JGOKWg(UjgsFlo) {" fullword ascii
    $s19 = "function PigSeXRdj(upOVcQijffm) {" fullword ascii
    $s20 = "return tWPKY.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}