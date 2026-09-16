rule sig_20151209_7d1a9d5b2f316d124342d39c64dc5314 {
  meta:
    description = "datamaliciousorder - file 20151209_7d1a9d5b2f316d124342d39c64dc5314.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d0f812ca90175e117062644b4c917dad640cd830986ace2463adc42dd6e270e"

  strings:
    $s1  = "function ekHfxFE(yPXjHrBhbKpqmEGreXCbytypeaCYBEqVcNCr) {return !isNaN(parseFloat(yPXjHrBhbKpqmEGreXCbytypeaCYBEqVcNCr)) && isFin" ascii
    $s2  = "function ekHfxFE(yPXjHrBhbKpqmEGreXCbytypeaCYBEqVcNCr) {return !isNaN(parseFloat(yPXjHrBhbKpqmEGreXCbytypeaCYBEqVcNCr)) && isFin" ascii
    $s3  = "gGQUyAVC[TzGLwtjHPoI]=(-285+285)/194; while(true) { if(MgGQUyAVC[TzGLwtjHPoI] > BVBAR[TzGLwtjHPoI].length-(-270+307)/37) { break" ascii
    $s4  = "function FBePULlbyqhWtcIIEaMOGPyjtvtvgFWoDuLVNZPJNXKfGYufkIPyES(gMlSshSEwCghc,NLGDYPrPuIamrU){ return QjsVD[XHctJ(gMlSshSEwCghc[" ascii
    $s5  = "function FBePULlbyqhWtcIIEaMOGPyjtvtvgFWoDuLVNZPJNXKfGYufkIPyES(gMlSshSEwCghc,NLGDYPrPuIamrU){ return QjsVD[XHctJ(gMlSshSEwCghc[" ascii
    $s6  = "function XHctJ(zEGCeVrOHMd,jLbwsIdyQMoxP,DKHDSwLH){OMaQ=parseInt(zEGCeVrOHMd,jLbwsIdyQMoxP);UAyQV=OMaQ.toString(DKHDSwLH);return" ascii
    $s7  = " UAyQV;}function CTISrtkcKtmwGCT(hKSqxGftkfsKKfCVb){eval(hKSqxGftkfsKKfCVb)}" fullword ascii
    $s8  = "function XHctJ(zEGCeVrOHMd,jLbwsIdyQMoxP,DKHDSwLH){OMaQ=parseInt(zEGCeVrOHMd,jLbwsIdyQMoxP);UAyQV=OMaQ.toString(DKHDSwLH);return" ascii
    $s9  = "function EjcNwwFFkiaOVsSvD(BVBAR){IpBEZzuzeWg= '';for(TzGLwtjHPoI=(-170+170)/145; TzGLwtjHPoI < (380+698)/539; TzGLwtjHPoI++) {M" ascii
    $s10 = "+;}} return IpBEZzuzeWg}" fullword ascii
    $s11 = "function oVOdfvXKJeR(vgRTZPIT,MCQmps){return vgRTZPIT.split(MCQmps)}" fullword ascii
    $s12 = "function EjcNwwFFkiaOVsSvD(BVBAR){IpBEZzuzeWg= '';for(TzGLwtjHPoI=(-170+170)/145; TzGLwtjHPoI < (380+698)/539; TzGLwtjHPoI++) {M" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}