rule sig_20151210_62182f9e442ffc1060464c7a8ad180df {
  meta:
    description = "datamaliciousorder - file 20151210_62182f9e442ffc1060464c7a8ad180df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "017e9c2d6491121cb428061431cfcbafdb3acdc547ccd89a16194093f7f6bae2"

  strings:
    $s1  = "function kwFvajI(HrYvSzmABgDakfmdGKdxgmPVxZoRGcUXMPLX) {return !isNaN(parseFloat(HrYvSzmABgDakfmdGKdxgmPVxZoRGcUXMPLX)) && isFin" ascii
    $s2  = "function kwFvajI(HrYvSzmABgDakfmdGKdxgmPVxZoRGcUXMPLX) {return !isNaN(parseFloat(HrYvSzmABgDakfmdGKdxgmPVxZoRGcUXMPLX)) && isFin" ascii
    $s3  = "function EHglBBBkKIvtFovmGVboNeLDcoXxDOlDgpvsNQbjnBgpFXENDBJZSj(oyiggPcuptcls,ehPdNzENnuBbGI){ return qzILOQXlunrwh[dDJpD(oyiggP" ascii
    $s4  = "function dDJpD(QbmSCkXsHwD,zeLNKcZqlnlWQ,zXHalsRU){haqu=parseInt(QbmSCkXsHwD,zeLNKcZqlnlWQ);soLEV=haqu.toString(zXHalsRU);return" ascii
    $s5  = "PeAvdBb=(-70+70)/51;while(true){if(PeAvdBb>=(4997+123)/40){break;}qzILOQXlunrwh[PeAvdBb]=String.fromCharCode(PeAvdBb);PeAvdBb++;" ascii
    $s6  = " soLEV;}function WbkYcQXSGZUzRKP(XIQckRclKQiCFjgDf){eval(XIQckRclKQiCFjgDf)}" fullword ascii
    $s7  = "function dDJpD(QbmSCkXsHwD,zeLNKcZqlnlWQ,zXHalsRU){haqu=parseInt(QbmSCkXsHwD,zeLNKcZqlnlWQ);soLEV=haqu.toString(zXHalsRU);return" ascii
    $s8  = "function EHglBBBkKIvtFovmGVboNeLDcoXxDOlDgpvsNQbjnBgpFXENDBJZSj(oyiggPcuptcls,ehPdNzENnuBbGI){ return qzILOQXlunrwh[dDJpD(oyiggP" ascii
    $s9  = "function hvfWBXSJmrakXhiLC(CWgpU){qzyfPlSpPmT= '';for(wfprtzEzIFR=(-123+123)/692; wfprtzEzIFR < (809+265)/537; wfprtzEzIFR++) {E" ascii
    $s10 = "function hvfWBXSJmrakXhiLC(CWgpU){qzyfPlSpPmT= '';for(wfprtzEzIFR=(-123+123)/692; wfprtzEzIFR < (809+265)/537; wfprtzEzIFR++) {E" ascii
    $s11 = "function bjNSsPthQiA(BvbKRTZp,rayQaz){return BvbKRTZp.split(rayQaz)}" fullword ascii
    $s12 = "}} return qzyfPlSpPmT}" fullword ascii
    $s13 = "hkvnGBEF[wfprtzEzIFR]=(-199+199)/491; while(true) { if(EhkvnGBEF[wfprtzEzIFR] > CWgpU[wfprtzEzIFR].length-(189+305)/494) { break" ascii
    $s14 = "PeAvdBb=(-70+70)/51;while(true){if(PeAvdBb>=(4997+123)/40){break;}qzILOQXlunrwh[PeAvdBb]=String.fromCharCode(PeAvdBb);PeAvdBb++;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}