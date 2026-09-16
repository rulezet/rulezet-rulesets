rule sig_20160411_47964e2c442b1afa8b7e20e9fbf9131a {
  meta:
    description = "datamaliciousorder - file 20160411_47964e2c442b1afa8b7e20e9fbf9131a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f8e789d1e12407b01a465fed3b875718aeec67ce17dfee7b235df17076f4938"

  strings:
    $s1  = "return ryJZ[loGWwBt[0]+loGWwBt[1]];" fullword ascii
    $s2  = "return IaodHsI[0] + IaodHsI[2] + IaodHsI[4] + \".F\" + IaodHsI[7] + IaodHsI[9] + IaodHsI[12] + IaodHsI[14];" fullword ascii
    $s3  = "var vi = true  , iDZM = GwY[7] + GwY[9] + GwY[11];" fullword ascii
    $s4  = "var GwY = (\"2.XMLHTTP LHNqJJW dRoFF XML ream St rwhJDEqG AD ljMeIIT O Tbzt D\").split(\" \");" fullword ascii
    $s5  = "xmgv.open(phcVx,duPLg,false);" fullword ascii
    $s6  = "if(N>=x.length) {break;}" fullword ascii
    $s7  = "function cfRd(kuCTf) {" fullword ascii
    $s8  = "function nCiupGPHe(ojzyy) {" fullword ascii
    $s9  = "return gmMrOHm[0];" fullword ascii
    $s10 = "function MYBa(cgTsR) {" fullword ascii
    $s11 = "function udmX(ibOKv,dtxlv) {" fullword ascii
    $s12 = "if (ISrMN > 198530-532){return true;} else {return false;}" fullword ascii
    $s13 = "return \"YlEWRqemwerUeL\";" fullword ascii
    $s14 = "function znRAK(EQiJObOp,SXHa) {" fullword ascii
    $s15 = "return XjtBegN;" fullword ascii
    $s16 = "return GeHHE;" fullword ascii
    $s17 = "return bOg.size;" fullword ascii
    $s18 = "return NDZ[bBIK[0]](UqfyW);" fullword ascii
    $s19 = "function SbGwVld(qGXi,EbyDr) {" fullword ascii
    $s20 = "function HOGIDm(WqGF,ILDrzZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}