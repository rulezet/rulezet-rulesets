rule sig_20151214_2981eede0d9c7d0d76e83a2e67e4a489 {
  meta:
    description = "datamaliciousorder - file 20151214_2981eede0d9c7d0d76e83a2e67e4a489.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1897c9bd06eac5291ac5379af685871aaf6f5e58dee679e3698e6163061efd5c"

  strings:
    $s1  = "Math.pow(Math.cos(488), 2) - 1)); while(true) { if(erxhVRBOx[CCzprkbMpvo] > ccHhg[CCzprkbMpvo].length-(57+103)/160) { break; } i" ascii
    $s2  = ".pow(Math.cos(205), 2) - 1)));} erxhVRBOx[CCzprkbMpvo]++;}} return hidJnjSdUvJ}" fullword ascii
    $s3  = "function alrmERSZYTqwZplju(ccHhg){hidJnjSdUvJ= x[1735];for(CCzprkbMpvo=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.co" ascii
    $s4  = "UPbgPlsfwkApXCmnnfBtuczYWVmdbmWYspDy([ccHhg[CCzprkbMpvo][erxhVRBOx[CCzprkbMpvo]]], Math.round((Math.pow(Math.sin(205), 2) + Math" ascii
    $s5  = "function alrmERSZYTqwZplju(ccHhg){hidJnjSdUvJ= x[1735];for(CCzprkbMpvo=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.co" ascii
    $s6  = "SkDn)) {return (String.fromCharCode(SojPGelisojiSkDn) + String.fromCharCode((61344+198)/789));}}" fullword ascii
    $s7  = "function e(QEreGwzNAyzi,PfcclwiQRmpkjj){QEreGwzNAyzi.push(PfcclwiQRmpkjj);}function C9(SojPGelisojiSkDn){if(FqRzzrb(SojPGelisoji" ascii
    $s8  = "function FqRzzrb(zYalsWfQilnpPjMRvqvHHFqsnNacfArbPlvh) {return !isNaN(parseFloat(zYalsWfQilnpPjMRvqvHHFqsnNacfArbPlvh)) && isFin" ascii
    $s9  = "function FqRzzrb(zYalsWfQilnpPjMRvqvHHFqsnNacfArbPlvh) {return !isNaN(parseFloat(zYalsWfQilnpPjMRvqvHHFqsnNacfArbPlvh)) && isFin" ascii
    $s10 = "function zBLDj(nStYXrafaXz,uWRQSIrKZBfOq,eZirWmCe){iGQc=parseInt(nStYXrafaXz,uWRQSIrKZBfOq);FGvFN=iGQc.toString(eZirWmCe);return" ascii
    $s11 = "function qoQGMBKbbad(FAdfaxbW,dUVAFg){return FAdfaxbW.split(dUVAFg)}" fullword ascii
    $s12 = " FGvFN;}function AdLZzwTAhHkwVFn(lMcxsajeLbkuMGpjE,ptVRFKkXRTMcKDoxjHrWfYkIWXzTFRByTi,vWkKcKIiHPviRYmZQSXEeOeamSlLQugWEfg){eval(" ascii
    $s13 = "function e(QEreGwzNAyzi,PfcclwiQRmpkjj){QEreGwzNAyzi.push(PfcclwiQRmpkjj);}function C9(SojPGelisojiSkDn){if(FqRzzrb(SojPGelisoji" ascii
    $s14 = "var x=new Array();" fullword ascii
    $s15 = "function AdLZzwTAhHkwVFn(lMcxsajeLbkuMGpjE){eval(lMcxsajeLbkuMGpjE)}" fullword ascii
    $s16 = "function RHBFgTtGBWsYSbZIwlUPbgPlsfwkApXCmnnfBtuczYWVmdbmWYspDy(rZdAPNbAqhaJC,JqCimNbQiIFHUj){ return NXwJzqU[dpqyzBIc[zBLDj(rZd" ascii
    $s17 = "function RHBFgTtGBWsYSbZIwlUPbgPlsfwkApXCmnnfBtuczYWVmdbmWYspDy(rZdAPNbAqhaJC,JqCimNbQiIFHUj){ return NXwJzqU[dpqyzBIc[zBLDj(rZd" ascii
    $s18 = "function zBLDj(nStYXrafaXz,uWRQSIrKZBfOq,eZirWmCe){iGQc=parseInt(nStYXrafaXz,uWRQSIrKZBfOq);FGvFN=iGQc.toString(eZirWmCe);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}