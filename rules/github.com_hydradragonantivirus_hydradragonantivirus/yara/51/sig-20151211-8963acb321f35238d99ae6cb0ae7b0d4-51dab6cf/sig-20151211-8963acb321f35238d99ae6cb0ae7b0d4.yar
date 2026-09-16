rule sig_20151211_8963acb321f35238d99ae6cb0ae7b0d4 {
  meta:
    description = "datamaliciousorder - file 20151211_8963acb321f35238d99ae6cb0ae7b0d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61020c71d980ff928d9eea80a5b9199b01fa640ce9bcf2460ca2309e709e93e9"

  strings:
    $s1  = "function WQUMjrS(uTxjUBqDErhpOJrGVUGxcrsWKNlZWTiWyUSs) {return !isNaN(parseFloat(uTxjUBqDErhpOJrGVUGxcrsWKNlZWTiWyUSs)) && isFin" ascii
    $s2  = "function WQUMjrS(uTxjUBqDErhpOJrGVUGxcrsWKNlZWTiWyUSs) {return !isNaN(parseFloat(uTxjUBqDErhpOJrGVUGxcrsWKNlZWTiWyUSs)) && isFin" ascii
    $s3  = "function KxdnMBzfoIQmEljGzCRMyWihrdAbNZPxKFhpyIpGFdsftSFJjvrvVX(XQjnelkopPzkz,FRjLciBfsZqHZg){ return uOhzv[DGNGT(XQjnelkopPzkz[" ascii
    $s4  = "var F=new Array(\"2a\",\"2b\",\"2c\",\"2d\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "function DGNGT(DGjkeCSJYvN,ZDJHPGIsarpEI,SdwnYnAX){eYch=parseInt(DGjkeCSJYvN,ZDJHPGIsarpEI);kDRaP=eYch.toString(SdwnYnAX);return" ascii
    $s6  = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function JPOPPmglOHq(AAFVxWVP,GFveyb){return AAFVxWVP.split(GFveyb)}" fullword ascii
    $s8  = "function DGNGT(DGjkeCSJYvN,ZDJHPGIsarpEI,SdwnYnAX){eYch=parseInt(DGjkeCSJYvN,ZDJHPGIsarpEI);kDRaP=eYch.toString(SdwnYnAX);return" ascii
    $s9  = "function KxdnMBzfoIQmEljGzCRMyWihrdAbNZPxKFhpyIpGFdsftSFJjvrvVX(XQjnelkopPzkz,FRjLciBfsZqHZg){ return uOhzv[DGNGT(XQjnelkopPzkz[" ascii
    $s10 = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var F=new Array(\"2a\",\"2b\",\"2c\",\"2d\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = "+;}NUJrUutcnMu++;} return SaJohHAGrIP}" fullword ascii
    $s13 = "function KqUfZpSwkoxfclwqB(edMSR){SaJohHAGrIP= '';NUJrUutcnMu=(-712+712)/216; while(true){if(NUJrUutcnMu >= (710+490)/600)break;" ascii
    $s14 = "function KqUfZpSwkoxfclwqB(edMSR){SaJohHAGrIP= '';NUJrUutcnMu=(-712+712)/216; while(true){if(NUJrUutcnMu >= (710+490)/600)break;" ascii
    $s15 = "MDDoMTNPs[NUJrUutcnMu]=(-902+902)/730; while(true) { if(MDDoMTNPs[NUJrUutcnMu] > edMSR[NUJrUutcnMu].length-(-44+744)/700) { brea" ascii
    $s16 = " kDRaP;}function alRgUkdVDsmerxW(bhXywolCzPVZwpEHi){eval(bhXywolCzPVZwpEHi)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}