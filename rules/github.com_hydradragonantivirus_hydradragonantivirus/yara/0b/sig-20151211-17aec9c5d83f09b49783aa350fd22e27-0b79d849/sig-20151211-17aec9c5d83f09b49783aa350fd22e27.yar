rule sig_20151211_17aec9c5d83f09b49783aa350fd22e27 {
  meta:
    description = "datamaliciousorder - file 20151211_17aec9c5d83f09b49783aa350fd22e27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27db981c441220e743bd93a8eff956eb547fdb1bf79b0c9d6321cc263c3872f0"

  strings:
    $s1  = "function WKreEXo(FoDDWzsZyENiaHudJNkfeAzeFLwWaosKjuBV) {return !isNaN(parseFloat(FoDDWzsZyENiaHudJNkfeAzeFLwWaosKjuBV)) && isFin" ascii
    $s2  = "function WKreEXo(FoDDWzsZyENiaHudJNkfeAzeFLwWaosKjuBV) {return !isNaN(parseFloat(FoDDWzsZyENiaHudJNkfeAzeFLwWaosKjuBV)) && isFin" ascii
    $s3  = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function jhPrJzEnaMASoCfZa(xpLtR){jpvYHWdogVn= '';gIriNmUEIij=(-655+655)/952; while(true){if(gIriNmUEIij >= (-301+443)/71)break;" ascii
    $s5  = "var c=new Array(\"2b\",\"2b\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s6  = "function cfrCp(zqSMnIvleQn,oyXgjwtCuAvoX,SITTbEIE){BRfO=parseInt(zqSMnIvleQn,oyXgjwtCuAvoX);IAmBT=BRfO.toString(SITTbEIE);return" ascii
    $s7  = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "function cfrCp(zqSMnIvleQn,oyXgjwtCuAvoX,SITTbEIE){BRfO=parseInt(zqSMnIvleQn,oyXgjwtCuAvoX);IAmBT=BRfO.toString(SITTbEIE);return" ascii
    $s9  = "function jhPrJzEnaMASoCfZa(xpLtR){jpvYHWdogVn= '';gIriNmUEIij=(-655+655)/952; while(true){if(gIriNmUEIij >= (-301+443)/71)break;" ascii
    $s10 = "var c=new Array(\"2b\",\"2b\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s11 = "function khnkgNHJoSQcFvXDgnGVHfBjaiztlyfnklygXjEeTkBdqQPRwcmGhI(NSrQciaDtkTgC,rSvUSWyEKhfoRy){ return ILXyR[cfrCp(NSrQciaDtkTgC[" ascii
    $s12 = "function CnafYBPbFjP(dXNfToFH,XeakzL){return dXNfToFH.split(XeakzL)}" fullword ascii
    $s13 = " IAmBT;}function jXypsqLSPTRNAch(FLtXonufmXKRMZumM){eval(FLtXonufmXKRMZumM)}" fullword ascii
    $s14 = "YECNTOVaK[gIriNmUEIij]=(-500+500)/124; while(true) { if(YECNTOVaK[gIriNmUEIij] > xpLtR[gIriNmUEIij].length-(129+547)/676) { brea" ascii
    $s15 = "function khnkgNHJoSQcFvXDgnGVHfBjaiztlyfnklygXjEeTkBdqQPRwcmGhI(NSrQciaDtkTgC,rSvUSWyEKhfoRy){ return ILXyR[cfrCp(NSrQciaDtkTgC[" ascii
    $s16 = "+;}gIriNmUEIij++;} return jpvYHWdogVn}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}