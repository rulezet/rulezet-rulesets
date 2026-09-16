rule sig_20160311_9c3b7d4f81c1db91062c1b8f1ebea8b6 {
  meta:
    description = "datamaliciousorder - file 20160311_9c3b7d4f81c1db91062c1b8f1ebea8b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43435d53fa229fad4ec244c9f4d422b266cf11005db593c64da90b086e65f046"

  strings:
    $s1  = "var qX = true  , Rqvf = DGF[7] + DGF[9] + DGF[11];" fullword ascii
    $s2  = "return CVjQkNP[0] + CVjQkNP[2] + CVjQkNP[4] + \".F\" + CVjQkNP[7] + CVjQkNP[9] + CVjQkNP[12] + CVjQkNP[14];" fullword ascii
    $s3  = "var DGF = (\"2.XMLHTTP ZfCofMp eALvT XML ream St cPdqvgRZ AD pDwxWGH O hGFf D\").split(\" \");" fullword ascii
    $s4  = "var CVjQkNP = \"Sc yuRhIXJ r bYGlwCfBp ipting yYWVPyu Gnh ile tBwILYlZVPJdFf System ii sKPTY Obj RMoWxn ect dyzkXZD\".split(\" " ascii
    $s5  = "function tLhlVxwZI(PLVTYQcMDIs) {" fullword ascii
    $s6  = "iTSGK.open(sCeBc,rrLFV,false);" fullword ascii
    $s7  = "function nnvK(wdody) {" fullword ascii
    $s8  = "return RPkJc.status;" fullword ascii
    $s9  = "function ywgU(QKDsh) {" fullword ascii
    $s10 = "function IXoKJjeS(IJj) {" fullword ascii
    $s11 = "return QoeZeig(rL,fjmgS[584-578]+fjmgS[769-762]+fjmgS[552-544]);" fullword ascii
    $s12 = "function pqub(iTSGK,rrLFV,sCeBc) {" fullword ascii
    $s13 = "function BFZESmiSB() {" fullword ascii
    $s14 = "if (Yifqa > 123741-403){return true;} else {return false;}" fullword ascii
    $s15 = "function DHltgdH(smiw) {" fullword ascii
    $s16 = "function afckhblF() {" fullword ascii
    $s17 = "function qkeIWMqw(Dpowt,XKnPXB) {" fullword ascii
    $s18 = "return gFDnskW" fullword ascii
    $s19 = "function QDmN(Kzyzk) {" fullword ascii
    $s20 = "return new ActiveXObject(XvPmLB);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}