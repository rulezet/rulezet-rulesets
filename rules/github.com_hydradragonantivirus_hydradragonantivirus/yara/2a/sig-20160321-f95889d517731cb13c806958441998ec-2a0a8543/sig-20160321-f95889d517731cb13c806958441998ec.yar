rule sig_20160321_f95889d517731cb13c806958441998ec {
  meta:
    description = "datamaliciousorder - file 20160321_f95889d517731cb13c806958441998ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fab76ca88a0581a39e48e74aadb9402e75e06b245f95adf9f97c93ec8da4a953"

  strings:
    $s1  = "return WScript.CreateObject(cPXvA);" fullword ascii
    $s2  = "var mx = true  , VxkV = arQ[7] + arQ[9] + arQ[11];" fullword ascii
    $s3  = "return HzKslPh[0] + HzKslPh[2] + HzKslPh[4] + \".F\" + HzKslPh[7] + HzKslPh[9] + HzKslPh[12] + HzKslPh[14];" fullword ascii
    $s4  = "var HzKslPh = VbGGT(KeSUScOLBB+\" \"+\"System LL OuJtX Obj TTaMjp ect fjRFDSd RPtTg\", \" \");" fullword ascii
    $s5  = "var arQ = (\"2.XMLHTTP TJQzGiX YJgPb XML ream St rHHRJtpP AD huZTOdx O wYAc D\").split(\" \");" fullword ascii
    $s6  = "AZXvO.open(VUWhr,EvFfE,false);" fullword ascii
    $s7  = "function NFYT(vSmWU) {" fullword ascii
    $s8  = "function ynJO(VgApN) {" fullword ascii
    $s9  = "if (DTUnM > 175182-625){return true;} else {return false;}" fullword ascii
    $s10 = "if(j>=g.length) {break;}" fullword ascii
    $s11 = "return jypgW;" fullword ascii
    $s12 = "return echXTe.position=678-678;" fullword ascii
    $s13 = "if (bPhoi == 974-774){return true;} else {return false;}" fullword ascii
    $s14 = "function HCnRUve(ZlVJ) {" fullword ascii
    $s15 = "function ZWlf(xyUHk) {" fullword ascii
    $s16 = "function TdZFmnS(qxvW,PyLSu) {" fullword ascii
    $s17 = "function YCll(cPXvA) {" fullword ascii
    $s18 = "function iRDFCXHMF(GeKFRtIJHlj) {" fullword ascii
    $s19 = "function wyvpskDg(SJP) {" fullword ascii
    $s20 = "return TdZFmnS(dr,MYTRN[973-967]+MYTRN[179-172]+MYTRN[928-920]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}