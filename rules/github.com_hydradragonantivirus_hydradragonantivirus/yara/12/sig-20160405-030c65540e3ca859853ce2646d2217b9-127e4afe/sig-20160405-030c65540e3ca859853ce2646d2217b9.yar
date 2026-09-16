rule sig_20160405_030c65540e3ca859853ce2646d2217b9 {
  meta:
    description = "datamaliciousorder - file 20160405_030c65540e3ca859853ce2646d2217b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00c43b11fa0e897ad030463b89e6ee03bc4484cd09bae540f8efb6680a916ee9"

  strings:
    $s1  = "var iy = true  , roZK = LGf[7] + LGf[9] + LGf[11];" fullword ascii
    $s2  = "return hwGGemY[0] + hwGGemY[2] + hwGGemY[4] + \".F\" + hwGGemY[7] + hwGGemY[9] + hwGGemY[12] + hwGGemY[14];" fullword ascii
    $s3  = "var LGf = (\"2.XMLHTTP UrcXfJD tYrKl XML ream St DahgZFUL AD mXzLDVx O YPht D\").split(\" \");" fullword ascii
    $s4  = "Zebh.open(npZOs,OlNBP,false);" fullword ascii
    $s5  = "function GiggWfnS(jyx) {" fullword ascii
    $s6  = "return EeHuQFs[0];" fullword ascii
    $s7  = "function tluus(wqP,ZXWAi) {" fullword ascii
    $s8  = "function wpNganS(wbVZ,GvDZq) {" fullword ascii
    $s9  = "return zNmgn;" fullword ascii
    $s10 = "return \"EXErZYudBkvFhE\";" fullword ascii
    $s11 = "return jyx.size;" fullword ascii
    $s12 = "return wqP.split(ZXWAi);" fullword ascii
    $s13 = "function euhENBp(GWoo) {" fullword ascii
    $s14 = "Ahg = S; break; " fullword ascii
    $s15 = "function kxiC(QkvHq,GPmZo) {" fullword ascii
    $s16 = "if (eyjrW == 402-202){return true;} else {return false;}" fullword ascii
    $s17 = "function QNgXNQFz(aJqk) {" fullword ascii
    $s18 = "function REOC(MDGoc) {" fullword ascii
    $s19 = "return wpNganS(lO,yxHNR[881-875]+yxHNR[922-915]+yxHNR[626-618]);" fullword ascii
    $s20 = "function lbkC(uecwg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}