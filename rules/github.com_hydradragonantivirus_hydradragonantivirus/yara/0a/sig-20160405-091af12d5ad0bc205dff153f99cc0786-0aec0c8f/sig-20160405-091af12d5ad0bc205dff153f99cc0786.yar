rule sig_20160405_091af12d5ad0bc205dff153f99cc0786 {
  meta:
    description = "datamaliciousorder - file 20160405_091af12d5ad0bc205dff153f99cc0786.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f230c645a08a80b8559b06eaed30fe0f18b7ca369ba67cf4e6e6948a97f4d7c6"

  strings:
    $s1  = "return CXqHutZ[0] + CXqHutZ[2] + CXqHutZ[4] + \".F\" + CXqHutZ[7] + CXqHutZ[9] + CXqHutZ[12] + CXqHutZ[14];" fullword ascii
    $s2  = "var et = true  , HHeu = fME[7] + fME[9] + fME[11];" fullword ascii
    $s3  = "iEAp.open(Yamfx,Kdoco,false);" fullword ascii
    $s4  = "var fME = (\"2.XMLHTTP PEBMHJx UHFEk XML ream St DqmtJNyz AD GPxTzzP O gsuN D\").split(\" \");" fullword ascii
    $s5  = "return zmcN[WYZxnt[0]];" fullword ascii
    $s6  = "function CvOE(PbKji) {" fullword ascii
    $s7  = "function iUNzZWT(SBhE,yvGYt) {" fullword ascii
    $s8  = "function UKkO(wlIeA,gjhVe) {" fullword ascii
    $s9  = "function HPPrHQb(zmcN) {" fullword ascii
    $s10 = "function fGlO(ujOet) {" fullword ascii
    $s11 = "function ksbm(quACi) {" fullword ascii
    $s12 = "if(y>=f.length) {break;}" fullword ascii
    $s13 = "function hXEkA(xtf,SWIoz) {" fullword ascii
    $s14 = "function hAIgDORLP(zbIga) {" fullword ascii
    $s15 = "return ocLe;" fullword ascii
    $s16 = "return xtf.split(SWIoz);" fullword ascii
    $s17 = "return TNQcj;" fullword ascii
    $s18 = "function kbnFK(KbbQrR) {" fullword ascii
    $s19 = "return nRUTI.status;" fullword ascii
    $s20 = "return \"qoDOzUHFsRdkmB\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}