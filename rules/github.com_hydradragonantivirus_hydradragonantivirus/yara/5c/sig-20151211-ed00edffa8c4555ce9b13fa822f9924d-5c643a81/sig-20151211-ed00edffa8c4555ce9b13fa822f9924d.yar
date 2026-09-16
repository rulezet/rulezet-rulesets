rule sig_20151211_ed00edffa8c4555ce9b13fa822f9924d {
  meta:
    description = "datamaliciousorder - file 20151211_ed00edffa8c4555ce9b13fa822f9924d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e28095df7023c3c1748ee65259d688ab131c987d1e2fcfcab8747867296f86de"

  strings:
    $s1  = "function vhaAXwf(WOhOpXPPtgOhSnUJrPCgZtWOBJoNKycvOtWR) {return !isNaN(parseFloat(WOhOpXPPtgOhSnUJrPCgZtWOBJoNKycvOtWR)) && isFin" ascii
    $s2  = "function vhaAXwf(WOhOpXPPtgOhSnUJrPCgZtWOBJoNKycvOtWR) {return !isNaN(parseFloat(WOhOpXPPtgOhSnUJrPCgZtWOBJoNKycvOtWR)) && isFin" ascii
    $s3  = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function kmgqunwnaApwLsdIASaynQdDKVTNNmuLxyLtJgNNPwSqNOeRTazeBL(dsZEUYnPnEGld,nxVYJAqyYUDTPX){ return pqdql[iXyUo(dsZEUYnPnEGld[" ascii
    $s5  = "PRsyimpA[dSzdKXWnAJy]=(-153+153)/380; while(true) { if(lPRsyimpA[dSzdKXWnAJy] > GrcYF[dSzdKXWnAJy].length-(-848+884)/36) { break" ascii
    $s6  = "function XEStJJkWBXKrODkMG(GrcYF){iontvNAffVs= '';dSzdKXWnAJy=(-669+669)/47; while(true){if(dSzdKXWnAJy >= (971+799)/885)break;l" ascii
    $s7  = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = " ilJnF;}function yBlbqLjVLnJQJtk(YqJXLhXHIOGJwTwEw){eval(YqJXLhXHIOGJwTwEw)}" fullword ascii
    $s9  = "function kCHTAullGsG(haSzxjCL,GPmqEE){return haSzxjCL.split(GPmqEE)}" fullword ascii
    $s10 = "function iXyUo(bIpmINetOQY,YkpExaNhFmruM,dXKzdLqS){hAxr=parseInt(bIpmINetOQY,YkpExaNhFmruM);ilJnF=hAxr.toString(dXKzdLqS);return" ascii
    $s11 = "+;}dSzdKXWnAJy++;} return iontvNAffVs}" fullword ascii
    $s12 = "function iXyUo(bIpmINetOQY,YkpExaNhFmruM,dXKzdLqS){hAxr=parseInt(bIpmINetOQY,YkpExaNhFmruM);ilJnF=hAxr.toString(dXKzdLqS);return" ascii
    $s13 = "var p=new Array(\"2f\",\"2f\",\"29\",\"2c\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s14 = "function XEStJJkWBXKrODkMG(GrcYF){iontvNAffVs= '';dSzdKXWnAJy=(-669+669)/47; while(true){if(dSzdKXWnAJy >= (971+799)/885)break;l" ascii
    $s15 = "var p=new Array(\"2f\",\"2f\",\"29\",\"2c\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s16 = "function kmgqunwnaApwLsdIASaynQdDKVTNNmuLxyLtJgNNPwSqNOeRTazeBL(dsZEUYnPnEGld,nxVYJAqyYUDTPX){ return pqdql[iXyUo(dsZEUYnPnEGld[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}