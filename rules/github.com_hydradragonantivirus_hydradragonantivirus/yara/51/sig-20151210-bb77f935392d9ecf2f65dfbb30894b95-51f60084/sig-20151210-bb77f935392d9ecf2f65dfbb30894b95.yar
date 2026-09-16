rule sig_20151210_bb77f935392d9ecf2f65dfbb30894b95 {
  meta:
    description = "datamaliciousorder - file 20151210_bb77f935392d9ecf2f65dfbb30894b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fcd1623d523f6e8ecccb450dbdb3883a1a0baf328c2503e8b27d045f3c941ec"

  strings:
    $s1  = "function CnAhXwU(ipAWbSGXFumAuGPsUGhMwFlfXmKJYEaTVoZU) {return !isNaN(parseFloat(ipAWbSGXFumAuGPsUGhMwFlfXmKJYEaTVoZU)) && isFin" ascii
    $s2  = "function CnAhXwU(ipAWbSGXFumAuGPsUGhMwFlfXmKJYEaTVoZU) {return !isNaN(parseFloat(ipAWbSGXFumAuGPsUGhMwFlfXmKJYEaTVoZU)) && isFin" ascii
    $s3  = "function gyZemwPqKsbDhiHUc(jHxxO){ylFLGPVSHqD= '';for(TBQNtptFnHB=(-283+283)/971; TBQNtptFnHB < (557+521)/539; TBQNtptFnHB++) {P" ascii
    $s4  = "+;}} return ylFLGPVSHqD}" fullword ascii
    $s5  = "XgdoLAL=(-932+932)/863;while(true){if(XgdoLAL>=(99811+925)/787){break;}HcOjGIZApbGvG[XgdoLAL]=String.fromCharCode(XgdoLAL);XgdoL" ascii
    $s6  = "function FhgauQubKGySwDsibVcmegYFbMTvRUbMfLlczutdinwKQEdshqVpWY(hrWajtNRtKoHe,pAwkBBoMOVWuVz){ return HcOjGIZApbGvG[uhNPk(hrWajt" ascii
    $s7  = "JqELzRyW[TBQNtptFnHB]=(-600+600)/379; while(true) { if(PJqELzRyW[TBQNtptFnHB] > jHxxO[TBQNtptFnHB].length-(-249+668)/419) { brea" ascii
    $s8  = "XgdoLAL=(-932+932)/863;while(true){if(XgdoLAL>=(99811+925)/787){break;}HcOjGIZApbGvG[XgdoLAL]=String.fromCharCode(XgdoLAL);XgdoL" ascii
    $s9  = "function uhNPk(fsMgYRZeFoM,cFvxEYgsbSFCt,NqoDdPpf){BJYT=parseInt(fsMgYRZeFoM,cFvxEYgsbSFCt);agISr=BJYT.toString(NqoDdPpf);return" ascii
    $s10 = "function rafKjqmxVZk(MZPmzrtF,GpcbvA){return MZPmzrtF.split(GpcbvA)}" fullword ascii
    $s11 = "function gyZemwPqKsbDhiHUc(jHxxO){ylFLGPVSHqD= '';for(TBQNtptFnHB=(-283+283)/971; TBQNtptFnHB < (557+521)/539; TBQNtptFnHB++) {P" ascii
    $s12 = "function FhgauQubKGySwDsibVcmegYFbMTvRUbMfLlczutdinwKQEdshqVpWY(hrWajtNRtKoHe,pAwkBBoMOVWuVz){ return HcOjGIZApbGvG[uhNPk(hrWajt" ascii
    $s13 = " agISr;}function DipCxXmFIOTivMW(XLCgsahadAjVMvRtp){eval(XLCgsahadAjVMvRtp)}" fullword ascii
    $s14 = "function uhNPk(fsMgYRZeFoM,cFvxEYgsbSFCt,NqoDdPpf){BJYT=parseInt(fsMgYRZeFoM,cFvxEYgsbSFCt);agISr=BJYT.toString(NqoDdPpf);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}