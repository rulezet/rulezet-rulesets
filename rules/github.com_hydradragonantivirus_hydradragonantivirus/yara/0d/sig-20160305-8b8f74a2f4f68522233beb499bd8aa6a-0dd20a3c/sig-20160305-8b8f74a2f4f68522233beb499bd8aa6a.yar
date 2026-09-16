rule sig_20160305_8b8f74a2f4f68522233beb499bd8aa6a {
  meta:
    description = "datamaliciousorder - file 20160305_8b8f74a2f4f68522233beb499bd8aa6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c04f188d47d950e50e444936c33704286e34c5b2321018bfaf55481bafcc5db"

  strings:
    $s1  = "var cOCBV = \"Crmgnn fmA pt.Shell nxEpNld Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return huOAFjS[0] + huOAFjS[2] + huOAFjS[4] + \".F\" + huOAFjS[7] + huOAFjS[9] + huOAFjS[12] + huOAFjS[14];" fullword ascii
    $s3  = "var sPG = (llw + \"TTP\" + \" ZWZomBW mmDUy XML ream St fAMjxuao AD yzgrjVC OD\").split(\" \");" fullword ascii
    $s4  = "var Bs = true  , sOXC = sPG[7] + \"\" + sPG[9];" fullword ascii
    $s5  = "qVlmn.open(JiAGN,HzAVv,false);" fullword ascii
    $s6  = "var huOAFjS = \"Sc SbKbYTY r VVxFjEwWr ipting ZhLpTbT lHO ile bohCtSWLhASMpS System uR FDHKM Obj iqcDsI ect snFWuyd\".split(\" " ascii
    $s7  = "function PsFp(OkoNA) {" fullword ascii
    $s8  = "function OtOJppYLc(aQpNfdgVQBQ) {" fullword ascii
    $s9  = "function bERsn(XGRvew) {" fullword ascii
    $s10 = "return ffnuomK" fullword ascii
    $s11 = "if(m>=M.length) {break;}" fullword ascii
    $s12 = "PK = 1; iuyszVf(fSG);hEST(fSG,/*xfCk51b96G*/OyqJ/*dtfH61jiXc*/+cVMHqMx+PoC[7]+PoC[8]); try  {" fullword ascii
    $s13 = "function ocEp(qVlmn,HzAVv,JiAGN) {" fullword ascii
    $s14 = "function WACxYvDD() {" fullword ascii
    $s15 = "return JCHbk;" fullword ascii
    $s16 = "function ntXN(qBxVZ,ByFWI) {" fullword ascii
    $s17 = "return hhBoO.status;" fullword ascii
    $s18 = "function MyCc(hhBoO) {" fullword ascii
    $s19 = "function FWZf(zbfYt) {" fullword ascii
    $s20 = "function iuyszVf(WxOU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}