rule sig_20160309_675a2027d49dd12b3431de65d5eb7256 {
  meta:
    description = "datamaliciousorder - file 20160309_675a2027d49dd12b3431de65d5eb7256.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e908af5eb8e6edaf0da8df07bf65cb5a47c39c5837826ead29d4f51d556127ae"

  strings:
    $s1  = "var ZFzYwUQ = \"Sc fEtlFDk r JGOElVlkm ipting ElueRet lEv ile zTLwgfYIZydkqg System FQ QCOmN Obj VLSjaC ect hHTPbjj\".split(\" " ascii
    $s2  = "return ZFzYwUQ[0] + ZFzYwUQ[2] + ZFzYwUQ[4] + \".F\" + ZFzYwUQ[7] + ZFzYwUQ[9] + ZFzYwUQ[12] + ZFzYwUQ[14];" fullword ascii
    $s3  = "var cX = true  , lhQg = kqA[7] + kqA[9] + kqA[11];" fullword ascii
    $s4  = "var kqA = (\"2.XMLHTTP pcVSceZ cyegX XML ream St oychfZlG AD pORvwQH O MPMz D\").split(\" \");" fullword ascii
    $s5  = "VdLtk.open(oAhTA,OgJbb,false);" fullword ascii
    $s6  = "if(R>=q.length) {break;}" fullword ascii
    $s7  = "function tbMT(kScHY,SlRlZ) {" fullword ascii
    $s8  = "gdq = R; break; " fullword ascii
    $s9  = "return ZsLwC;" fullword ascii
    $s10 = "return pyt.size;" fullword ascii
    $s11 = "return ucwYI.status;" fullword ascii
    $s12 = "function qOksuXy(lPJG,pwQPB) {" fullword ascii
    $s13 = "var XE = PAha(VE).split(\" \");" fullword ascii
    $s14 = "return IVFSICR" fullword ascii
    $s15 = "function ioXj(jtOzE) {" fullword ascii
    $s16 = "function jbNo(ucwYI) {" fullword ascii
    $s17 = "function CMJC(MNBqd) {" fullword ascii
    $s18 = "if (sQcxr > 190034-590){return true;} else {return false;}" fullword ascii
    $s19 = "return kTbe.responseBody;" fullword ascii
    $s20 = "function PAha(odauv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}