rule sig_20160314_214fa1955ae4065f88971ca675b1f118 {
  meta:
    description = "datamaliciousorder - file 20160314_214fa1955ae4065f88971ca675b1f118.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402de0606c2ebae8b72b75d9ae3d06b806e25bc7b75432da2fd99647f0f0ddf"

  strings:
    $s1  = "var LE = true  , ZlCX = RQP[7] + RQP[9] + RQP[11];" fullword ascii
    $s2  = "return RMqeMvt[0] + RMqeMvt[2] + RMqeMvt[4] + \".F\" + RMqeMvt[7] + RMqeMvt[9] + RMqeMvt[12] + RMqeMvt[14];" fullword ascii
    $s3  = "var RMqeMvt = \"Sc tseVSat r QrvyNPyhk ipting WcVYHkJ DmY ile ghoIwnqoIefrSh System VK nHxBf Obj AJaQKH ect kwfYseq Gcfos\".spli" ascii
    $s4  = "var RMqeMvt = \"Sc tseVSat r QrvyNPyhk ipting WcVYHkJ DmY ile ghoIwnqoIefrSh System VK nHxBf Obj AJaQKH ect kwfYseq Gcfos\".spli" ascii
    $s5  = "qVewS.open(PrOJy,JPpNF,false);" fullword ascii
    $s6  = "var RQP = (\"2.XMLHTTP VouiVNt fxzKT XML ream St dMvmUZVQ AD tQgzjwq O kSNF D\").split(\" \");" fullword ascii
    $s7  = "function IbiG(EmJtU) {" fullword ascii
    $s8  = "if(U>=k.length) {break;}" fullword ascii
    $s9  = "if (uEPPh > 198019-471){return true;} else {return false;}" fullword ascii
    $s10 = "return ZNnumIQ(cq,zOtQI[654-648]+zOtQI[383-376]+zOtQI[666-658]);" fullword ascii
    $s11 = "function ZNnumIQ(CXdp,YJgDj) {" fullword ascii
    $s12 = "function yjbB(uEPPh) {" fullword ascii
    $s13 = "return siCcZvs" fullword ascii
    $s14 = "function JZZc(AdHFZ) {" fullword ascii
    $s15 = "function IrFt(yRLbY) {" fullword ascii
    $s16 = "function rkuz(AXsUO) {" fullword ascii
    $s17 = "function NmJB(qVewS,JPpNF,PrOJy) {" fullword ascii
    $s18 = "function xxQcLkQE() {" fullword ascii
    $s19 = "return new ActiveXObject(hWDXHZ);" fullword ascii
    $s20 = "oSy = U; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}