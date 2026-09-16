rule sig_20160404_6d135454d63c2783e3faa79a54e93b2c {
  meta:
    description = "datamaliciousorder - file 20160404_6d135454d63c2783e3faa79a54e93b2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9ffa91346b96b217e3fb05a9525e3962afe89b75a4c8524755ff23b6762cd79"

  strings:
    $s1  = "var lJ = true  , bgfL = sXt[7] + sXt[9] + sXt[11];" fullword ascii
    $s2  = "return YWvBYCQ[0] + YWvBYCQ[2] + YWvBYCQ[4] + \".F\" + YWvBYCQ[7] + YWvBYCQ[9] + YWvBYCQ[12] + YWvBYCQ[14];" fullword ascii
    $s3  = "var YWvBYCQ = BSoFW(fiuKHbFgSU+\" \"+\"System Mh mUPTI Obj CyVYSD ect ZPIcNch gKQhk\", \" \");" fullword ascii
    $s4  = "oSnv.open(Bpfwp,FVsuj,false);" fullword ascii
    $s5  = "var sXt = (\"2.XMLHTTP HRekKzg utIUd XML ream St RqhBhbyy AD yrcNiqh O qidK D\").split(\" \");" fullword ascii
    $s6  = "if(T>=P.length) {break;}" fullword ascii
    $s7  = "function ykqhlFsO(RUb) {" fullword ascii
    $s8  = "function wPGdFq(YNmrLdJ) {" fullword ascii
    $s9  = "function pzGIpDCDf(OWFVr) {" fullword ascii
    $s10 = "function aujw(fGqcf,JQYSJ) {" fullword ascii
    $s11 = "FUXA(kgR); kgR.type = 1; ltgv(kgR,SFNshky(Ta)); if (dont(ykqhlFsO(kgR)))  {" fullword ascii
    $s12 = "function GNmW(PTvTS) {" fullword ascii
    $s13 = "if (cEABA == 1088-888){return true;} else {return false;}" fullword ascii
    $s14 = "function GWOYOO(kmLj,wAjNYI) {" fullword ascii
    $s15 = "return \"TAICLpglVkbMtC\";" fullword ascii
    $s16 = "return MUpbFqh;" fullword ascii
    $s17 = "return cbW.split(septL);" fullword ascii
    $s18 = "function UZubraII(sPUi) {" fullword ascii
    $s19 = "return EqSQ[qWdZeA[0]];" fullword ascii
    $s20 = "function FUXA(TOfha) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}