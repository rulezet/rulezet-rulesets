rule sig_20160321_dec744b0177a055ccef258f855d18d71 {
  meta:
    description = "datamaliciousorder - file 20160321_dec744b0177a055ccef258f855d18d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "591c5022f179e4cb4490e12f19c17618bb8455168b4c28ee9106b8834a4c2db7"

  strings:
    $s1  = "return WScript.CreateObject(FMbpT);" fullword ascii
    $s2  = "return yrotGPn[0] + yrotGPn[2] + yrotGPn[4] + \".F\" + yrotGPn[7] + yrotGPn[9] + yrotGPn[12] + yrotGPn[14];" fullword ascii
    $s3  = "var KY = true  , yVzg = Jmc[7] + Jmc[9] + Jmc[11];" fullword ascii
    $s4  = "var yrotGPn = TXcbh(sSzihwMoLj+\" \"+\"System HA HVohy Obj awJkfP ect wcfkTtB aBjPc\", \" \");" fullword ascii
    $s5  = "var Jmc = (\"2.XMLHTTP JKaaNsF BTKuM XML ream St XysWwgwW AD nXHaTqy O crwF D\").split(\" \");" fullword ascii
    $s6  = "aXTVT.open(IpSsm,ROBNG,false);" fullword ascii
    $s7  = "function uCnXQ(MTYfVH) {" fullword ascii
    $s8  = "return KGF.split(xLmPe);" fullword ascii
    $s9  = "function TXcbh(KGF,xLmPe) {" fullword ascii
    $s10 = "function wFICCuB(XhjO,GrxLK) {" fullword ascii
    $s11 = "return pxUnt;" fullword ascii
    $s12 = "function EZiF(FMbpT) {" fullword ascii
    $s13 = "function ugFZ(iBTaa) {" fullword ascii
    $s14 = "function GHQY(bnYuO) {" fullword ascii
    $s15 = "return wFICCuB(ix,jhRES[249-243]+jhRES[943-936]+jhRES[648-640]);" fullword ascii
    $s16 = "function ktoxmOq(XJgF) {" fullword ascii
    $s17 = "return new ActiveXObject(MTYfVH);" fullword ascii
    $s18 = "return iBTaa.status;" fullword ascii
    $s19 = "function kxJEVUxzc(oKTsCQyrzKw) {" fullword ascii
    $s20 = "return XhjO.ExpandEnvironmentStrings(GrxLK);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}