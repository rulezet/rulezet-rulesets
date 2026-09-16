rule sig_20151211_65e3ebbf66188166c28eee9d7f366c85 {
  meta:
    description = "datamaliciousorder - file 20151211_65e3ebbf66188166c28eee9d7f366c85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90aa0d2379ed2d7b530c5722996402a3fd8675532e5fcac56400c6a3b47bef32"

  strings:
    $s1  = "function PUHpDFH(yIJJaHKMymLuiSgCKxVymwKEDhCOWbvFxwyb) {return !isNaN(parseFloat(yIJJaHKMymLuiSgCKxVymwKEDhCOWbvFxwyb)) && isFin" ascii
    $s2  = "function PUHpDFH(yIJJaHKMymLuiSgCKxVymwKEDhCOWbvFxwyb) {return !isNaN(parseFloat(yIJJaHKMymLuiSgCKxVymwKEDhCOWbvFxwyb)) && isFin" ascii
    $s3  = "function zztlj(fXcURVpSIOI,GJavMuLHemYbz,WBuJkwnq){ykFs=parseInt(fXcURVpSIOI,GJavMuLHemYbz);uobzV=ykFs.toString(WBuJkwnq);return" ascii
    $s4  = "function lUbowNVBIUVPSVpxx(SKmDn){CIoFuaegSbO= '';hGJmveiHWbR=(-908+908)/445; while(true){if(hGJmveiHWbR >= (468+132)/300)break;" ascii
    $s5  = "var X=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = " uobzV;}function AHkqnnckSYLTNpx(CFgQyHKgxBAbZlypi){eval(CFgQyHKgxBAbZlypi)}" fullword ascii
    $s7  = "function zztlj(fXcURVpSIOI,GJavMuLHemYbz,WBuJkwnq){ykFs=parseInt(fXcURVpSIOI,GJavMuLHemYbz);uobzV=ykFs.toString(WBuJkwnq);return" ascii
    $s8  = "function lUbowNVBIUVPSVpxx(SKmDn){CIoFuaegSbO= '';hGJmveiHWbR=(-908+908)/445; while(true){if(hGJmveiHWbR >= (468+132)/300)break;" ascii
    $s9  = "function GFBYUbuHNzxpTVmxEaptKNesKgpIXQDPUAMUJMLzrGgqndaZMsxaRY(IRotUHvckGcQQ,QqjyduAQBFNJdn){ return oXSjn[zztlj(IRotUHvckGcQQ[" ascii
    $s10 = "var j=new Array(\"26\",\"2d\",\"2d\",\"2e\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "bBNPjZaGG[hGJmveiHWbR]=(-535+535)/70; while(true) { if(bBNPjZaGG[hGJmveiHWbR] > SKmDn[hGJmveiHWbR].length-(-185+594)/409) { brea" ascii
    $s12 = "var j=new Array(\"26\",\"2d\",\"2d\",\"2e\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function jvnGVMnDBkk(YvltTJWd,dvYNtD){return YvltTJWd.split(dvYNtD)}" fullword ascii
    $s14 = "var X=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "]++;}hGJmveiHWbR++;} return CIoFuaegSbO}" fullword ascii
    $s16 = "function GFBYUbuHNzxpTVmxEaptKNesKgpIXQDPUAMUJMLzrGgqndaZMsxaRY(IRotUHvckGcQQ,QqjyduAQBFNJdn){ return oXSjn[zztlj(IRotUHvckGcQQ[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}