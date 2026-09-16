rule sig_20151214_62d564dbb8338e90acbe570f41436604 {
  meta:
    description = "datamaliciousorder - file 20151214_62d564dbb8338e90acbe570f41436604.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c79e7f564797b52c0e1e69d79a3ef544f091bf5ae1b9756e7bcb00e86239609"

  strings:
    $s1  = "function mpClovDLLyHejJTaY(DMLwX){QFfORyompGD= s[1735];for(GxAZGHKszdl=Math.round((Math.pow(Math.sin(827), 2) + Math.pow(Math.co" ascii
    $s2  = "Math.pow(Math.cos(948), 2) - 1)); while(true) { if(FZvGaFbnW[GxAZGHKszdl] > DMLwX[GxAZGHKszdl].length-(13+202)/215) { break; } i" ascii
    $s3  = "function mpClovDLLyHejJTaY(DMLwX){QFfORyompGD= s[1735];for(GxAZGHKszdl=Math.round((Math.pow(Math.sin(827), 2) + Math.pow(Math.co" ascii
    $s4  = "ow(Math.cos(465), 2) - 1)));} FZvGaFbnW[GxAZGHKszdl]++;}} return QFfORyompGD}" fullword ascii
    $s5  = "function jR(bHBXqiWZyDkO,FPDLznxvpLeTzv){bHBXqiWZyDkO.push(FPDLznxvpLeTzv);}function O8(REOJxGcFOXiHDdBb){if(mAhelMH(REOJxGcFOXi" ascii
    $s6  = "HDdBb)) {return (String.fromCharCode(REOJxGcFOXiHDdBb) + String.fromCharCode((7084+836)/165));}}" fullword ascii
    $s7  = "function mAhelMH(OCvicKhhZGhNtZNjgccPMMhvgOIZOwaqQxnv) {return !isNaN(parseFloat(OCvicKhhZGhNtZNjgccPMMhvgOIZOwaqQxnv)) && isFin" ascii
    $s8  = "function mAhelMH(OCvicKhhZGhNtZNjgccPMMhvgOIZOwaqQxnv) {return !isNaN(parseFloat(OCvicKhhZGhNtZNjgccPMMhvgOIZOwaqQxnv)) && isFin" ascii
    $s9  = "var s=new Array();" fullword ascii
    $s10 = "function aQnHipEjeFxxaKzDlSnjlUmECWhamZyTxwVxNsWBvsjCwjEOEhWqEl(WcmfGFkuYmOTJ,YIbaOQZrDCZyvz){ return vcUlARL[MTssVsRl[SMvRN(Wcm" ascii
    $s11 = "function aQnHipEjeFxxaKzDlSnjlUmECWhamZyTxwVxNsWBvsjCwjEOEhWqEl(WcmfGFkuYmOTJ,YIbaOQZrDCZyvz){ return vcUlARL[MTssVsRl[SMvRN(Wcm" ascii
    $s12 = " KNuSE;}function RxXUzauHCHEdtpV(lcvGBqklxaFPHCXOA,gVwgHicMwiFHaiYJXTxFGdhnvnLSGiRQhz,ldksRJMZMKbYSXQyNHuCKDNZsEqBmZzzTCf){eval(" ascii
    $s13 = "function YvUZeVdgfiP(CpidQhqE,IQtzJC){return CpidQhqE.split(IQtzJC)}" fullword ascii
    $s14 = "function jR(bHBXqiWZyDkO,FPDLznxvpLeTzv){bHBXqiWZyDkO.push(FPDLznxvpLeTzv);}function O8(REOJxGcFOXiHDdBb){if(mAhelMH(REOJxGcFOXi" ascii
    $s15 = "function RxXUzauHCHEdtpV(lcvGBqklxaFPHCXOA){eval(lcvGBqklxaFPHCXOA)}" fullword ascii
    $s16 = "function SMvRN(dAkfHNcAdsp,EfSThqYsVTBbW,VXbwxPIk){bfrr=parseInt(dAkfHNcAdsp,EfSThqYsVTBbW);KNuSE=bfrr.toString(VXbwxPIk);return" ascii
    $s17 = "function SMvRN(dAkfHNcAdsp,EfSThqYsVTBbW,VXbwxPIk){bfrr=parseInt(dAkfHNcAdsp,EfSThqYsVTBbW);KNuSE=bfrr.toString(VXbwxPIk);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}