rule sig_20160411_ea61edb93b2d740603137da59e58b255 {
  meta:
    description = "datamaliciousorder - file 20160411_ea61edb93b2d740603137da59e58b255.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2f82bb559d11c27559e08504887e8d66ed99b2a69e0448bcc94c339bd37719"

  strings:
    $s1  = "var bs = true  , Jdsi = KCS[7] + KCS[9] + KCS[11];" fullword ascii
    $s2  = "return skgpvEH[0] + skgpvEH[2] + skgpvEH[4] + \".F\" + skgpvEH[7] + skgpvEH[9] + skgpvEH[12] + skgpvEH[14];" fullword ascii
    $s3  = "dXBJ.open(sdmRs,SrEjN,false);" fullword ascii
    $s4  = "var KCS = (\"2.XMLHTTP GSMTTNV kYHAW XML ream St ZxYKMePS AD oQAiRVY O udyd D\").split(\" \");" fullword ascii
    $s5  = "function LKyl(DadzK) {" fullword ascii
    $s6  = "function ZrktST(nyaNrHG) {" fullword ascii
    $s7  = "if (tKHtK > 166805-935){return true;} else {return false;}" fullword ascii
    $s8  = "return Qgc[BJdn[0]](yOmXs);" fullword ascii
    $s9  = "function PNnlxOve(zbP) {" fullword ascii
    $s10 = "if (o >= EJLKZ.length) {break;}" fullword ascii
    $s11 = "return SSpGCr[cQNG[329-329]]=212-212;" fullword ascii
    $s12 = "function yEty(vpZkr,aZCym) {" fullword ascii
    $s13 = "function XMZzsHs(jCuf) {" fullword ascii
    $s14 = "function ViSF(VszPS) {" fullword ascii
    $s15 = "function lnCS(waMpm) {" fullword ascii
    $s16 = "function EbBBOzdt(ktMU) {" fullword ascii
    $s17 = "function ToiOf(SSpGCr) {" fullword ascii
    $s18 = "jhp = F; break; " fullword ascii
    $s19 = "function lTuj(JFWSG) {" fullword ascii
    $s20 = "function FvketdXXA(SjrrX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}