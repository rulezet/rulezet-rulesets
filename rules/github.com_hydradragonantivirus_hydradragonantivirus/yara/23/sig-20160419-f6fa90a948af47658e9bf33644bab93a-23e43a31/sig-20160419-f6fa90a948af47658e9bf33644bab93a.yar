rule sig_20160419_f6fa90a948af47658e9bf33644bab93a {
  meta:
    description = "datamaliciousorder - file 20160419_f6fa90a948af47658e9bf33644bab93a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cfc1b3c3f0ecf79886651cbb39cf935ea5ed951385179e23fb8a629dd95116"

  strings:
    $s1  = "return hBTZDtd[0] + hBTZDtd[2] + hBTZDtd[4] + \".F\" + hBTZDtd[7] + hBTZDtd[9] + hBTZDtd[12] + hBTZDtd[14];" fullword ascii
    $s2  = "var el = true  , KkyP = kBL[7] + kBL[9] + kBL[11];" fullword ascii
    $s3  = "doVQ.open(JMQjN,iVjmV,false);" fullword ascii
    $s4  = "var kBL = (\"2.XMLHTTP ewWlnkv GaCfQ XML ream St sVOKplig AD KHjwOaC O GFur D\").split(\" \");" fullword ascii
    $s5  = "return JQSwjF[yvlz[240-240]]=685-685;" fullword ascii
    $s6  = "function kijC(kqtwC) {" fullword ascii
    $s7  = "function ckHY(woVlU,USGyX) {" fullword ascii
    $s8  = "if (ARqDP != 1172-972){return false;} else {return true;}" fullword ascii
    $s9  = "function hmMQcTW(xhSk) {" fullword ascii
    $s10 = "return kER.size;" fullword ascii
    $s11 = "function unxt(bywKA,iVjmV,JMQjN) {" fullword ascii
    $s12 = "return CRGsiDY(Eg,fUhKcy+GCEKq[810-802]);" fullword ascii
    $s13 = "function qMbbjAdJF(ZqGpJ) {" fullword ascii
    $s14 = "function SEJm(ARqDP) {" fullword ascii
    $s15 = "return JtyIX.status;" fullword ascii
    $s16 = "return XqlKLLV;" fullword ascii
    $s17 = "function tGHn(Ikrnx,UjVhZ) {" fullword ascii
    $s18 = "if(H>=m.length) {break;}" fullword ascii
    $s19 = "function YelptA(vXNcHdM) {" fullword ascii
    $s20 = "function CRGsiDY(MqpS,omwcQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}