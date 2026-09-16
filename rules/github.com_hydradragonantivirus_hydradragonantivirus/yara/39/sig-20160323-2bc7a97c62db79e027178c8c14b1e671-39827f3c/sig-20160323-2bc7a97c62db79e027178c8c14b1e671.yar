rule sig_20160323_2bc7a97c62db79e027178c8c14b1e671 {
  meta:
    description = "datamaliciousorder - file 20160323_2bc7a97c62db79e027178c8c14b1e671.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2da91b123522fc160e1f91ba29f679edd400f3dbc49467de9c9bb2338e816cfd"

  strings:
    $s1  = "return WScript.CreateObject(tMLZC);" fullword ascii
    $s2  = "var ON = true  , DbWs = hah[7] + hah[9] + hah[11];" fullword ascii
    $s3  = "return dvrPKBJ[0] + dvrPKBJ[2] + dvrPKBJ[4] + \".F\" + dvrPKBJ[7] + dvrPKBJ[9] + dvrPKBJ[12] + dvrPKBJ[14];" fullword ascii
    $s4  = "var hah = (\"2.XMLHTTP GMFrVpT oblTw XML ream St gyUDiOGT AD wfareph O nghP D\").split(\" \");" fullword ascii
    $s5  = "var dvrPKBJ = ieKnY(cJGTHSEise+\" \"+\"System Pc Wtyls Obj SUgccg ect LiJrZNl oRsQd\", \" \");" fullword ascii
    $s6  = "LsER.open(hpLET,cnklG,false);" fullword ascii
    $s7  = "function GzmaUyp(baQP) {" fullword ascii
    $s8  = "function Ngwo(XhceB,GEJuT) {" fullword ascii
    $s9  = "if (YOREb > 192477-497){return true;} else {return false;}" fullword ascii
    $s10 = "function VyCRA(jLIUHv) {" fullword ascii
    $s11 = "return DKGX.ExpandEnvironmentStrings(TOpyW);" fullword ascii
    $s12 = "return iwV.size;" fullword ascii
    $s13 = "return baQP[mqFEpa[0]];" fullword ascii
    $s14 = "function aYuZ(GiNpp) {" fullword ascii
    $s15 = "return UJZqb;" fullword ascii
    $s16 = "vrM = X; break; " fullword ascii
    $s17 = "function pHYe(uAmAZ) {" fullword ascii
    $s18 = "function cOtGNjK(DKGX,TOpyW) {" fullword ascii
    $s19 = "function RlRo(IpGIK) {" fullword ascii
    $s20 = "function mcyh(xyfXZ,cnklG,hpLET) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}