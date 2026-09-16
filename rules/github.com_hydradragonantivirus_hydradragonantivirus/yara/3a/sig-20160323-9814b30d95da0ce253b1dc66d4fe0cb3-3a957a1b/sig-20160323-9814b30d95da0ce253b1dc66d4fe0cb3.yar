rule sig_20160323_9814b30d95da0ce253b1dc66d4fe0cb3 {
  meta:
    description = "datamaliciousorder - file 20160323_9814b30d95da0ce253b1dc66d4fe0cb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93d18a20af965ef1d8ef377c5523b9a82aebc2bfe1e28a89f558e870544124d5"

  strings:
    $s1  = "return WScript.CreateObject(uMCrp);" fullword ascii
    $s2  = "return yCylUhW[0] + yCylUhW[2] + yCylUhW[4] + \".F\" + yCylUhW[7] + yCylUhW[9] + yCylUhW[12] + yCylUhW[14];" fullword ascii
    $s3  = "var Ac = true  , gTUL = Yga[7] + Yga[9] + Yga[11];" fullword ascii
    $s4  = "var yCylUhW = PpDDo(GDvfkqIDoq+\" \"+\"System PF cxhEJ Obj TcncRm ect OjxkURQ fdVRc\", \" \");" fullword ascii
    $s5  = "nWiN.open(ykBLe,LbupD,false);" fullword ascii
    $s6  = "var Yga = (\"2.XMLHTTP JdEhYcv vpfDl XML ream St vKuLcoSb AD mNphzAw O WAne D\").split(\" \");" fullword ascii
    $s7  = "oFT = B; break; " fullword ascii
    $s8  = "if (x >= XcDne.length) {break;}" fullword ascii
    $s9  = "if (OJvcJ > 174652-874){return true;} else {return false;}" fullword ascii
    $s10 = "function yeCV(UgwzF,ivFll) {" fullword ascii
    $s11 = "return yrWfwh/*UqgWK9XIJrenotQVZsxlLiNBk*/.position=371-371;" fullword ascii
    $s12 = "function qqWI(OJvcJ) {" fullword ascii
    $s13 = "function HwepDiKfo(HaHSE) {" fullword ascii
    $s14 = "function AXvkbnX(UtvQ) {" fullword ascii
    $s15 = "function NSIBUYvj(ENxt) {" fullword ascii
    $s16 = "return Wxt.split(haPOM);" fullword ascii
    $s17 = "function jAcZ(yAcDQ) {" fullword ascii
    $s18 = "function PpDDo(Wxt,haPOM) {" fullword ascii
    $s19 = "return new ActiveXObject(JBRQ);" fullword ascii
    $s20 = "return xBRPoll(JZ,NXCth[498-492]+NXCth[454-447]+NXCth[759-751]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}