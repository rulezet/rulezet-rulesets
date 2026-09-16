rule sig_20160302_60b624ef5e35395add2bfb0a150cd333 {
  meta:
    description = "datamaliciousorder - file 20160302_60b624ef5e35395add2bfb0a150cd333.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a03c94934d23cb60c21ac3acb9efc76d575b1ef40f4a0684d66b7b1cad64f8d"

  strings:
    $s1  = "var rc = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(XQzmn);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + kvRpBoi + \".F\" + hYKJanBklI + wFVnT + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var Yh = true  , iRZz = KWa[7] + \"\" + KWa[9];" fullword ascii
    $s5  = "var KWa = (sRB + \"TTP\" + \" msySIzl hoIrU XML ream St zFjhjQpB AD gZrnJlJ OD\").split(\" \");" fullword ascii
    $s6  = "ZfXAN.open(TOstS,UpRjV,false);" fullword ascii
    $s7  = "function kAwA(yDWwb) {" fullword ascii
    $s8  = "function noXk(LeCOL) {" fullword ascii
    $s9  = "function cUiN(NRCMe) {" fullword ascii
    $s10 = "function fiPB(XQzmn) {" fullword ascii
    $s11 = "function mMSfOiuim(SiwMD,WMJcj,qZUrw) {" fullword ascii
    $s12 = "function lxAe(HgOsc,UwARZ) {" fullword ascii
    $s13 = "function nMJu(YDfpH) {" fullword ascii
    $s14 = "function iNtZ(kAQAi,YOBKJ) {" fullword ascii
    $s15 = "function krJr(iklnb) {" fullword ascii
    $s16 = "return yDWwb.status;" fullword ascii
    $s17 = "return fNJFr;" fullword ascii
    $s18 = "function GoIR(ZfXAN,UpRjV,TOstS) {" fullword ascii
    $s19 = "EBs = w; break; " fullword ascii
    $s20 = "if(w>=X.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}