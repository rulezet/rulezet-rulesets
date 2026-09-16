rule sig_20151211_dd1c13cbf19a8669e02d0b7c2d4ade20 {
  meta:
    description = "datamaliciousorder - file 20151211_dd1c13cbf19a8669e02d0b7c2d4ade20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "215f078ff64267a47651e212315919a98c01143620a1a5bde231af7278e74111"

  strings:
    $s1  = "function iWAugOp(ovUWWHOBISPOKfDLkOtrcidLLSbKPZkkCQtQ) {return !isNaN(parseFloat(ovUWWHOBISPOKfDLkOtrcidLLSbKPZkkCQtQ)) && isFin" ascii
    $s2  = "function iWAugOp(ovUWWHOBISPOKfDLkOtrcidLLSbKPZkkCQtQ) {return !isNaN(parseFloat(ovUWWHOBISPOKfDLkOtrcidLLSbKPZkkCQtQ)) && isFin" ascii
    $s3  = "function UISSaNXmMyleMEQBsQBzjnLNjBZnFvIYaCiynDGhoYcwPfTfRTesIg(gafzlLPNSGfhX,AHyWjPTOeazghx){ return UxNfx[yVHWh(gafzlLPNSGfhX[" ascii
    $s4  = "var C=new Array(\"2c\",\"29\",\"2c\",\"28\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "function yVHWh(HtCZSfdtCym,qvwQFJeytQoxl,uMpuuVjb){KBBy=parseInt(HtCZSfdtCym,qvwQFJeytQoxl);utmEw=KBBy.toString(uMpuuVjb);return" ascii
    $s6  = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function AYPrbGkIsAeTqTldp(KFLoV){ggZCobRuaSA= '';DyASWHJCmNP=(-62+62)/678; while(true){if(DyASWHJCmNP >= (643+993)/818)break;dN" ascii
    $s8  = "DyASWHJCmNP++;} return ggZCobRuaSA}" fullword ascii
    $s9  = "function yVHWh(HtCZSfdtCym,qvwQFJeytQoxl,uMpuuVjb){KBBy=parseInt(HtCZSfdtCym,qvwQFJeytQoxl);utmEw=KBBy.toString(uMpuuVjb);return" ascii
    $s10 = "var C=new Array(\"2c\",\"29\",\"2c\",\"28\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "mhcqjnh[DyASWHJCmNP]=(-538+538)/52; while(true) { if(dNmhcqjnh[DyASWHJCmNP] > KFLoV[DyASWHJCmNP].length-(-595+605)/10) { break; " ascii
    $s12 = "function UISSaNXmMyleMEQBsQBzjnLNjBZnFvIYaCiynDGhoYcwPfTfRTesIg(gafzlLPNSGfhX,AHyWjPTOeazghx){ return UxNfx[yVHWh(gafzlLPNSGfhX[" ascii
    $s13 = "function KKGJsXrpfDh(MpsBFcuH,CWROOw){return MpsBFcuH.split(CWROOw)}" fullword ascii
    $s14 = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function AYPrbGkIsAeTqTldp(KFLoV){ggZCobRuaSA= '';DyASWHJCmNP=(-62+62)/678; while(true){if(DyASWHJCmNP >= (643+993)/818)break;dN" ascii
    $s16 = " utmEw;}function oyTJYFPnvqdzjiy(TcgUndIdhXDfQEOzA){eval(TcgUndIdhXDfQEOzA)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}