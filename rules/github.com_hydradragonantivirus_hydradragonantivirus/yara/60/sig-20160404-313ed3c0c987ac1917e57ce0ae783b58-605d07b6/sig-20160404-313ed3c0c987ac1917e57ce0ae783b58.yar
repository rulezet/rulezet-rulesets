rule sig_20160404_313ed3c0c987ac1917e57ce0ae783b58 {
  meta:
    description = "datamaliciousorder - file 20160404_313ed3c0c987ac1917e57ce0ae783b58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16597fefd3287904dbe2fd9b3a77303995e802a9b2e78a3067a89b7a88215fc7"

  strings:
    $s1  = "function deqt(spyyF) {" fullword ascii
    $s2  = "return YIiTVcX[0] + YIiTVcX[2] + YIiTVcX[4] + \".F\" + YIiTVcX[7] + YIiTVcX[9] + YIiTVcX[12] + YIiTVcX[14];" fullword ascii
    $s3  = "var sg = true  , LPAN = xqn[7] + xqn[9] + xqn[11];" fullword ascii
    $s4  = "knVR.open(XnAcP,CneaJ,false);" fullword ascii
    $s5  = "function BrUN(AgyTb,UvFHL) {" fullword ascii
    $s6  = "var xqn = (\"2.XMLHTTP eqhUkwe hBtaM XML ream St atEYiRZO AD zXdNuzo O Tlnj D\").split(\" \");" fullword ascii
    $s7  = "var YIiTVcX = vRvdK(PDaSSDMFqC+\" \"+\"System eb Zwigu Obj ZjDlyK ect zNvCJGG PVPSU\", \" \");" fullword ascii
    $s8  = "return ojxkeXV;" fullword ascii
    $s9  = "function IPHzb(qWBeNhOL,qRcI) {" fullword ascii
    $s10 = "function vRvdK(kro,BWuLU) {" fullword ascii
    $s11 = "return kro.split(BWuLU);" fullword ascii
    $s12 = "function hWWA(KBzTI) {" fullword ascii
    $s13 = "return HblTVpO(RP,DtkPS[974-968]+DtkPS[884-877]+DtkPS[805-797]);" fullword ascii
    $s14 = "function Zbgo(GDdWv) {" fullword ascii
    $s15 = "if (e >= aLehY.length) {break;}" fullword ascii
    $s16 = "function GHdJ(aLehY) {" fullword ascii
    $s17 = "function iSDjqy(mhHsKnk) {" fullword ascii
    $s18 = "function EFJY(sCYRl,CneaJ,XnAcP) {" fullword ascii
    $s19 = "if (AZLtg > 175456-168){return true;} else {return false;}" fullword ascii
    $s20 = "if(l>=h.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}