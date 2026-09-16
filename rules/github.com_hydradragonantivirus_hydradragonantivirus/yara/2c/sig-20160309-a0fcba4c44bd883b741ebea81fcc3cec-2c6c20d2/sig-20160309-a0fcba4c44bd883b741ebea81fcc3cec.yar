rule sig_20160309_a0fcba4c44bd883b741ebea81fcc3cec {
  meta:
    description = "datamaliciousorder - file 20160309_a0fcba4c44bd883b741ebea81fcc3cec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b847fcc6bb7f3ff4dc2133245eb3d4f6f2e334930ef5c0fd289ce62558a9cd31"

  strings:
    $s1  = "return Mayywti[0] + Mayywti[2] + Mayywti[4] + \".F\" + Mayywti[7] + Mayywti[9] + Mayywti[12] + Mayywti[14];" fullword ascii
    $s2  = "var kA = true  , Rcmf = xgW[7] + xgW[9] + xgW[11];" fullword ascii
    $s3  = "var xgW = (\"2.XMLHTTP pLRFJTW LoTAn XML ream St WgnXqioW AD zsJXCMB O HzRg D\").split(\" \");" fullword ascii
    $s4  = "var Mayywti = \"Sc IBopQNx r uoRWCPLIT ipting WCrGJUj SPP ile rGlUpNggwsigkn System Gk aDySt Obj zHyltn ect EWDVbxJ\".split(\" " ascii
    $s5  = "XVBQW.open(bBJtn,GfHKS,false);" fullword ascii
    $s6  = "bEi = C; break; " fullword ascii
    $s7  = "function AAxs(sdOSF) {" fullword ascii
    $s8  = "function zVPQ(XVBQW,GfHKS,bBJtn) {" fullword ascii
    $s9  = "if (MmRUB > 153954-251){return true;} else {return false;}" fullword ascii
    $s10 = "function bqPGWkC(Adrb) {" fullword ascii
    $s11 = "return fqw.size;" fullword ascii
    $s12 = "return lDXai;" fullword ascii
    $s13 = "function cmHp(ZFbpL,SuaHn) {" fullword ascii
    $s14 = "function sBrv(GkPNQ,UtKel) {" fullword ascii
    $s15 = "function ngfr(LVYup) {" fullword ascii
    $s16 = "function RrZbhizh(fqw) {" fullword ascii
    $s17 = "return Adrb.responseBody;" fullword ascii
    $s18 = "function IOVOYYYgw(jlJNoKcKIFf) {" fullword ascii
    $s19 = "function CcsK(oYkCc) {" fullword ascii
    $s20 = "function AJaRLlMaP(kwJJg,ScTbT,oiSny,nffw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}