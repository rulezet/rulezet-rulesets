rule sig_20151211_2834dcd5946df4485fe07a42d56a543b {
  meta:
    description = "datamaliciousorder - file 20151211_2834dcd5946df4485fe07a42d56a543b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63edd0e28426edf21043ddca10d1d0cf57844a514234a1954e65fdd53f58198a"

  strings:
    $s1  = "function sBkWmYz(REdZZHKJZKyxBVnukGhchvvxOtiqMkfmfkji) {return !isNaN(parseFloat(REdZZHKJZKyxBVnukGhchvvxOtiqMkfmfkji)) && isFin" ascii
    $s2  = "function sBkWmYz(REdZZHKJZKyxBVnukGhchvvxOtiqMkfmfkji) {return !isNaN(parseFloat(REdZZHKJZKyxBVnukGhchvvxOtiqMkfmfkji)) && isFin" ascii
    $s3  = "function ceNOTLMlqTmsvBXPb(imdqA){WMKpVokbUaJ= '';pbMXiVqsrkH=(-26+26)/685; while(true){if(pbMXiVqsrkH >= (829+477)/653)break;UJ" ascii
    $s4  = ";}pbMXiVqsrkH++;} return WMKpVokbUaJ}" fullword ascii
    $s5  = "function IXcZVekuxON(QSCvAobR,RqudQD){return QSCvAobR.split(RqudQD)}" fullword ascii
    $s6  = " ptPZr;}function JvMKPNFXQPDdIzM(XxMPlzhnIbeECbhlb){eval(XxMPlzhnIbeECbhlb)}" fullword ascii
    $s7  = "var E=new Array(\"2f\",\"2d\",\"26\",\"2c\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "function pzobf(ylCnqOCnbjM,lcHphkeOBIXXD,lDZhORTQ){YFbB=parseInt(ylCnqOCnbjM,lcHphkeOBIXXD);ptPZr=YFbB.toString(lDZhORTQ);return" ascii
    $s9  = "function ceNOTLMlqTmsvBXPb(imdqA){WMKpVokbUaJ= '';pbMXiVqsrkH=(-26+26)/685; while(true){if(pbMXiVqsrkH >= (829+477)/653)break;UJ" ascii
    $s10 = "XxADcgS[pbMXiVqsrkH]=(-267+267)/440; while(true) { if(UJXxADcgS[pbMXiVqsrkH] > imdqA[pbMXiVqsrkH].length-(-250+955)/705) { break" ascii
    $s11 = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function LqBqInhpqQcvjVIIPaCCoGNaMNmsBfaGLtZNGDboyTSBeabFpChOVF(wWaWdVIrGTDKt,thNzwUbybFsBwU){ return WXpdK[pzobf(wWaWdVIrGTDKt[" ascii
    $s13 = "var E=new Array(\"2f\",\"2d\",\"26\",\"2c\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = "function LqBqInhpqQcvjVIIPaCCoGNaMNmsBfaGLtZNGDboyTSBeabFpChOVF(wWaWdVIrGTDKt,thNzwUbybFsBwU){ return WXpdK[pzobf(wWaWdVIrGTDKt[" ascii
    $s15 = "function pzobf(ylCnqOCnbjM,lcHphkeOBIXXD,lDZhORTQ){YFbB=parseInt(ylCnqOCnbjM,lcHphkeOBIXXD);ptPZr=YFbB.toString(lDZhORTQ);return" ascii
    $s16 = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}