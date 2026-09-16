rule sig_20151211_3141c9a964feddcf6c7c457fbb032963 {
  meta:
    description = "datamaliciousorder - file 20151211_3141c9a964feddcf6c7c457fbb032963.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e79eb9bde7c30340a3777c533615881722af3c37c7ed742743071c56f130afca"

  strings:
    $s1  = "function JzizoCc(lihwPnxMOwVHfAUgcIfDfDkwaxhKyLHzQmcp) {return !isNaN(parseFloat(lihwPnxMOwVHfAUgcIfDfDkwaxhKyLHzQmcp)) && isFin" ascii
    $s2  = "function JzizoCc(lihwPnxMOwVHfAUgcIfDfDkwaxhKyLHzQmcp) {return !isNaN(parseFloat(lihwPnxMOwVHfAUgcIfDfDkwaxhKyLHzQmcp)) && isFin" ascii
    $s3  = ";vFEjUlrQi[oojPedQVGUt]=(-895+895)/983; while(true) { if(vFEjUlrQi[oojPedQVGUt] > OWpyb[oojPedQVGUt].length-(83+673)/756) { brea" ascii
    $s4  = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "var S=new Array(\"29\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"4k\",\"2j\",\"" ascii
    $s6  = "var S=new Array(\"29\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"4k\",\"2j\",\"" ascii
    $s7  = "function FrrOMRibDaFnAQVYsdxBpHdjSTPdMdBCzEBMHdfvOKRzqFnoGCcPeE(XDmDglACGYBCd,cWyQDzMaaljZRS){ return ngRxp[cURsz(XDmDglACGYBCd[" ascii
    $s8  = "function daMswOwYSFAQhHgYi(OWpyb){nOWpUVWuAXy= '';oojPedQVGUt=(-162+162)/730; while(true){if(oojPedQVGUt >= (1674+256)/965)break" ascii
    $s9  = " flibq;}function wLDpsRmxflduBJS(zXdPLnlJjUtkjyvIF){eval(zXdPLnlJjUtkjyvIF)}" fullword ascii
    $s10 = "]++;}oojPedQVGUt++;} return nOWpUVWuAXy}" fullword ascii
    $s11 = "function cURsz(hytIJdRNSQs,yevjazIUoMfGX,sLMqZKtc){omON=parseInt(hytIJdRNSQs,yevjazIUoMfGX);flibq=omON.toString(sLMqZKtc);return" ascii
    $s12 = "function WzEQRNhXPzv(GxzkJSUH,iVVXXq){return GxzkJSUH.split(iVVXXq)}" fullword ascii
    $s13 = "function cURsz(hytIJdRNSQs,yevjazIUoMfGX,sLMqZKtc){omON=parseInt(hytIJdRNSQs,yevjazIUoMfGX);flibq=omON.toString(sLMqZKtc);return" ascii
    $s14 = "function daMswOwYSFAQhHgYi(OWpyb){nOWpUVWuAXy= '';oojPedQVGUt=(-162+162)/730; while(true){if(oojPedQVGUt >= (1674+256)/965)break" ascii
    $s15 = "function FrrOMRibDaFnAQVYsdxBpHdjSTPdMdBCzEBMHdfvOKRzqFnoGCcPeE(XDmDglACGYBCd,cWyQDzMaaljZRS){ return ngRxp[cURsz(XDmDglACGYBCd[" ascii
    $s16 = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}