rule sig_20151210_c379cb4e22b53ddb88f77b517727e040 {
  meta:
    description = "datamaliciousorder - file 20151210_c379cb4e22b53ddb88f77b517727e040.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a845a66054ad2467e575859df2e67e5783e6f147becd09dd379230d30688d958"

  strings:
    $s1  = "function qBXjrNt(akuCUJXLrLIfFTaUKtsjnfdauYStJNQOpAxC) {return !isNaN(parseFloat(akuCUJXLrLIfFTaUKtsjnfdauYStJNQOpAxC)) && isFin" ascii
    $s2  = "function qBXjrNt(akuCUJXLrLIfFTaUKtsjnfdauYStJNQOpAxC) {return !isNaN(parseFloat(akuCUJXLrLIfFTaUKtsjnfdauYStJNQOpAxC)) && isFin" ascii
    $s3  = "function wulFIBGpjyZhivKCi(BDvId){jdXhgYYUqQb= '';for(UCGsugpLKIs=(-151+151)/488; UCGsugpLKIs < (1127+383)/755; UCGsugpLKIs++) {" ascii
    $s4  = "FMlDSsk=(-289+289)/70;while(true){if(FMlDSsk>=(90826+566)/714){break;}vzVbZEsDyLfMr[FMlDSsk]=String.fromCharCode(FMlDSsk);FMlDSs" ascii
    $s5  = "MhIRFALvZ[UCGsugpLKIs]=(-670+670)/734; while(true) { if(MhIRFALvZ[UCGsugpLKIs] > BDvId[UCGsugpLKIs].length-(122+523)/645) { brea" ascii
    $s6  = "function biDvT(xqcSGlQwmni,nzOskzskCDmNS,nqYohHkc){buPE=parseInt(xqcSGlQwmni,nzOskzskCDmNS);XKkhZ=buPE.toString(nqYohHkc);return" ascii
    $s7  = " XKkhZ;}function AJSKjVmNPqgjLEn(KLHjNzbqBstZNISoW){eval(KLHjNzbqBstZNISoW)}" fullword ascii
    $s8  = "function wulFIBGpjyZhivKCi(BDvId){jdXhgYYUqQb= '';for(UCGsugpLKIs=(-151+151)/488; UCGsugpLKIs < (1127+383)/755; UCGsugpLKIs++) {" ascii
    $s9  = "function KYgnTUAZGiI(sTyZamXF,vbxzpH){return sTyZamXF.split(vbxzpH)}" fullword ascii
    $s10 = "function qygoSqXjTJkEIoaUPByCpHqRHIgDByckxvBpHvuIiVMcylQqiEOIht(HEQLxlHXpiVMY,ZaFPesFwxOiviA){ return vzVbZEsDyLfMr[biDvT(HEQLxl" ascii
    $s11 = "]++;}} return jdXhgYYUqQb}" fullword ascii
    $s12 = "FMlDSsk=(-289+289)/70;while(true){if(FMlDSsk>=(90826+566)/714){break;}vzVbZEsDyLfMr[FMlDSsk]=String.fromCharCode(FMlDSsk);FMlDSs" ascii
    $s13 = "function biDvT(xqcSGlQwmni,nzOskzskCDmNS,nqYohHkc){buPE=parseInt(xqcSGlQwmni,nzOskzskCDmNS);XKkhZ=buPE.toString(nqYohHkc);return" ascii
    $s14 = "function qygoSqXjTJkEIoaUPByCpHqRHIgDByckxvBpHvuIiVMcylQqiEOIht(HEQLxlHXpiVMY,ZaFPesFwxOiviA){ return vzVbZEsDyLfMr[biDvT(HEQLxl" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}