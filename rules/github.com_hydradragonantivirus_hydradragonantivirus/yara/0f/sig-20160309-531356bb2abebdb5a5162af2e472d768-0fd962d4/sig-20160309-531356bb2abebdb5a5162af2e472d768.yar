rule sig_20160309_531356bb2abebdb5a5162af2e472d768 {
  meta:
    description = "datamaliciousorder - file 20160309_531356bb2abebdb5a5162af2e472d768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72592fe263d3b2bc45d6439fcfe9dcea3d2993d3b66fd2a6a1737664f23dacc9"

  strings:
    $s1  = "return gBYLEdM[0] + gBYLEdM[2] + gBYLEdM[4] + \".F\" + gBYLEdM[7] + gBYLEdM[9] + gBYLEdM[12] + gBYLEdM[14];" fullword ascii
    $s2  = "var Uo = true  , ubhq = ANe[7] + ANe[9] + ANe[11];" fullword ascii
    $s3  = "var gBYLEdM = \"Sc VXbtFqC r HchnBJkxI ipting LlUsHRB YNF ile ZWKoxbpAlaibMu System iA yviAf Obj NhdWEm ect StWJrWk\".split(\" " ascii
    $s4  = "gsERM.open(SejDR,ekVyD,false);" fullword ascii
    $s5  = "var ANe = (\"2.XMLHTTP xpsujiq LivJt XML ream St NJPbfqNE AD OExUTvT O kHKP D\").split(\" \");" fullword ascii
    $s6  = "return haicmQe" fullword ascii
    $s7  = "function ZLtH(bcYBF) {" fullword ascii
    $s8  = "function ZyPn(FQITQ) {" fullword ascii
    $s9  = "function NuZpGWPmV(VIkxT,ubowA,KpXij,ODDU) {" fullword ascii
    $s10 = "function jgCh(yPBNB,cFZXD) {" fullword ascii
    $s11 = "function aagotcOG(ESUUf,GTJBSN) {" fullword ascii
    $s12 = "function nHFrYeR(AzuT) {" fullword ascii
    $s13 = "return AzuT.responseBody;" fullword ascii
    $s14 = "return new ActiveXObject(YSlfMN);" fullword ascii
    $s15 = "if (xVDxX == 824-624){return true;} else {return false;}" fullword ascii
    $s16 = "function vCSOq(YSlfMN) {" fullword ascii
    $s17 = "if(K>=G.length) {break;}" fullword ascii
    $s18 = "function onrPYby(MEsG,hZyYk) {" fullword ascii
    $s19 = "return IwhaV;" fullword ascii
    $s20 = "return bcYBF.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}