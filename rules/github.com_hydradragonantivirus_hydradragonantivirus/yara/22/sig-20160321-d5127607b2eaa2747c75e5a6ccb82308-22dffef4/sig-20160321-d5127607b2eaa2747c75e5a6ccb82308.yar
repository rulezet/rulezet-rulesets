rule sig_20160321_d5127607b2eaa2747c75e5a6ccb82308 {
  meta:
    description = "datamaliciousorder - file 20160321_d5127607b2eaa2747c75e5a6ccb82308.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "594c6ef58263c604062e0fe13e78a44232e67a841dd41b572d9e056e5f96ba71"

  strings:
    $s1  = "return WScript.CreateObject(gpUiI);" fullword ascii
    $s2  = "var cT = true  , KOSq = AXd[7] + AXd[9] + AXd[11];" fullword ascii
    $s3  = "return gIqBRnV[0] + gIqBRnV[2] + gIqBRnV[4] + \".F\" + gIqBRnV[7] + gIqBRnV[9] + gIqBRnV[12] + gIqBRnV[14];" fullword ascii
    $s4  = "var gIqBRnV = qYpEg(DgxKtknAMT+\" \"+\"System VN lNdEG Obj FmlCTY ect NLJjbKQ XYwRM\", \" \");" fullword ascii
    $s5  = "kIrPg.open(ktOIs,PrmNC,false);" fullword ascii
    $s6  = "return XSBinR.position=427-427;" fullword ascii
    $s7  = "var AXd = (\"2.XMLHTTP dCIioTj FakDQ XML ream St dJYShoQL AD MdQBNGW O sbss D\").split(\" \");" fullword ascii
    $s8  = "function pmaUg(XSBinR) {" fullword ascii
    $s9  = "function DKhW(JRsdd) {" fullword ascii
    $s10 = "return Xuvrfja(Rk,eUVLS[149-143]+eUVLS[403-396]+eUVLS[276-268]);" fullword ascii
    $s11 = "function iGzVP(VcnpYz) {" fullword ascii
    $s12 = "function EAdE(vqccx) {" fullword ascii
    $s13 = "return DjHb[bwKOJY[0]];" fullword ascii
    $s14 = "return new ActiveXObject(VcnpYz);" fullword ascii
    $s15 = "function hQWAmrSH(HVG) {" fullword ascii
    $s16 = "function MPkv(KViRM,XXuVW) {" fullword ascii
    $s17 = "return ghN.split(gUuiy);" fullword ascii
    $s18 = "function UgPxLQCH(JFoX) {" fullword ascii
    $s19 = "function DkSFEpLSC(xVADN) {" fullword ascii
    $s20 = "function GTIK(ZtAON,nGcMG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}