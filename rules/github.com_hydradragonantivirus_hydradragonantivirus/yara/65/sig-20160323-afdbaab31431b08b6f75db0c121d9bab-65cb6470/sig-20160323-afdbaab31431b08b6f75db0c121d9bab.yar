rule sig_20160323_afdbaab31431b08b6f75db0c121d9bab {
  meta:
    description = "datamaliciousorder - file 20160323_afdbaab31431b08b6f75db0c121d9bab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b54fbb2947720090c358d8a7a0546bc82704aa6f53db84a7e82341dd2c43c917"

  strings:
    $s1  = "var xXi = (\"2.XMLHTTP EKeJGeS KhYtN XML ream St kEyPwtrv AD FKpEFPq O AlcP D\").split(\" \");" fullword ascii
    $s2  = "return WScript.CreateObject(uAfNp);" fullword ascii
    $s3  = "var UQ = true  , WzZg = xXi[7] + xXi[9] + xXi[11];" fullword ascii
    $s4  = "return rfkBWue[0] + rfkBWue[2] + rfkBWue[4] + \".F\" + rfkBWue[7] + rfkBWue[9] + rfkBWue[12] + rfkBWue[14];" fullword ascii
    $s5  = "var rfkBWue = rlGDI(ONVUPFjkhn+\" \"+\"System ey ImcmM Obj NwJlXF ect MNdYsAR SwGcS\", \" \");" fullword ascii
    $s6  = "vqyN.open(XXIGr,pdXGy,false);" fullword ascii
    $s7  = "function YEyW(yBJcy) {" fullword ascii
    $s8  = "function rtmI(hsmiV) {" fullword ascii
    $s9  = "return new ActiveXObject(AScV);" fullword ascii
    $s10 = "return tacY[NaaAbc[0]];" fullword ascii
    $s11 = "function YrGTepH(GeIR,LtDBr) {" fullword ascii
    $s12 = "function QMLY(wuqxY) {" fullword ascii
    $s13 = "function QEvm(xHpOn) {" fullword ascii
    $s14 = "if(V>=K.length) {break;}" fullword ascii
    $s15 = "if (yBJcy == 880-680){return true;} else {return false;}" fullword ascii
    $s16 = "return IQV.size;" fullword ascii
    $s17 = "function oWGHxDI(tacY) {" fullword ascii
    $s18 = "function svwg(uAfNp) {" fullword ascii
    $s19 = "return HAEsJ.status;" fullword ascii
    $s20 = "function rlGDI(Ttb,zIluE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}