rule sig_20160308_43bac9a2cf62330a683a38332635c487 {
  meta:
    description = "datamaliciousorder - file 20160308_43bac9a2cf62330a683a38332635c487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa8d8eec58ab992da089615f25686a747ea7f77b0d2854febf6cc9f2f29c31f"

  strings:
    $s1  = "var wd = true  , joPV = ChH[7] + ChH[9] + ChH[11];" fullword ascii
    $s2  = "return QOByGSy[0] + QOByGSy[2] + QOByGSy[4] + \".F\" + QOByGSy[7] + QOByGSy[9] + QOByGSy[12] + QOByGSy[14];" fullword ascii
    $s3  = "function DFEIoRun(cUb) {" fullword ascii
    $s4  = "var QOByGSy = \"Sc lVuYWAe r KxOuHIxLh ipting cECotyX TGs ile joRttZoUFerqoI System ul oZpsM Obj RKzTFM ect NQBtzIY\".split(\" " ascii
    $s5  = "edHkC.open(kHSVf,BjTUO,false);" fullword ascii
    $s6  = "var ChH = (\"2.XMLHTTP yHSnRJl foQRc XML ream St PyHZHpfb AD cBfPlFA O cSAd D\").split(\" \");" fullword ascii
    $s7  = "function FLKD(OrcJZ) {" fullword ascii
    $s8  = "if (mlwWA == 466-266){return true;} else {return false;}" fullword ascii
    $s9  = "function nvtYmvO(Ucmy) {" fullword ascii
    $s10 = "function svYMBaxS() {" fullword ascii
    $s11 = "wGq = M; break; " fullword ascii
    $s12 = "return new ActiveXObject(pDdTpy);" fullword ascii
    $s13 = "function RhXt(naztD) {" fullword ascii
    $s14 = "function qpLz(edHkC,BjTUO,kHSVf) {" fullword ascii
    $s15 = "return cUb.size;" fullword ascii
    $s16 = "function zJasRPhDf(fCxDm,idvBu,XgCCe,sSKw) {" fullword ascii
    $s17 = "function fVJDC(pDdTpy) {" fullword ascii
    $s18 = "function aDVn(iIUyZ,jpMHI) {" fullword ascii
    $s19 = "return OrcJZ.status;" fullword ascii
    $s20 = "if (fJOpG > 177742-944){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}