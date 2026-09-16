rule sig_20151209_ac9d5e611113aa2b5a573af1af9e7cbd {
  meta:
    description = "datamaliciousorder - file 20151209_ac9d5e611113aa2b5a573af1af9e7cbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04e1570707c9c756587d3cf22f9133c3f99695121d5aa6a0311435d2c4b39962"

  strings:
    $s1  = "function pNkQroq(VFTeUToPCQTzLwlWQRgGolJjqQjqxFcjlAYR) {return !isNaN(parseFloat(VFTeUToPCQTzLwlWQRgGolJjqQjqxFcjlAYR)) && isFin" ascii
    $s2  = "function pNkQroq(VFTeUToPCQTzLwlWQRgGolJjqQjqxFcjlAYR) {return !isNaN(parseFloat(VFTeUToPCQTzLwlWQRgGolJjqQjqxFcjlAYR)) && isFin" ascii
    $s3  = "function GnmwFlpdwPD(GMuTeGXC,DBBFIP){return GMuTeGXC.split(DBBFIP)}" fullword ascii
    $s4  = "function JXGjQgmcsIkxVogiuGXRsrcsKIGUaKBAYpJVxWrUkLzqFKylDhmHdi(IqpOiNvRFkRXs,tqQeargoazQGFq){ return kdDcP[fTVxE(IqpOiNvRFkRXs[" ascii
    $s5  = " return kHIlHGecMHB}" fullword ascii
    $s6  = "function JXGjQgmcsIkxVogiuGXRsrcsKIGUaKBAYpJVxWrUkLzqFKylDhmHdi(IqpOiNvRFkRXs,tqQeargoazQGFq){ return kdDcP[fTVxE(IqpOiNvRFkRXs[" ascii
    $s7  = "function fTVxE(nNSaOgsKYVG,GBOOLoyeRBUgy,hdlUmMrH){zdEs=parseInt(nNSaOgsKYVG,GBOOLoyeRBUgy);QtCes=zdEs.toString(hdlUmMrH);return" ascii
    $s8  = "zwCbbS[sizAOqHgdFV]=(-674+674)/659; while(true) { if(gSXzwCbbS[sizAOqHgdFV] > CAVrd[sizAOqHgdFV].length-(270+637)/907) { break; " ascii
    $s9  = "function fTVxE(nNSaOgsKYVG,GBOOLoyeRBUgy,hdlUmMrH){zdEs=parseInt(nNSaOgsKYVG,GBOOLoyeRBUgy);QtCes=zdEs.toString(hdlUmMrH);return" ascii
    $s10 = "function BThyGMvuhXimnewZj(CAVrd){kHIlHGecMHB= '';for(sizAOqHgdFV=(-30+30)/493; sizAOqHgdFV < (1341+19)/680; sizAOqHgdFV++) {gSX" ascii
    $s11 = " QtCes;}function msityvxTfVicahE(gCFGYGWbIoXByRDpn){eval(gCFGYGWbIoXByRDpn)}" fullword ascii
    $s12 = "function BThyGMvuhXimnewZj(CAVrd){kHIlHGecMHB= '';for(sizAOqHgdFV=(-30+30)/493; sizAOqHgdFV < (1341+19)/680; sizAOqHgdFV++) {gSX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}