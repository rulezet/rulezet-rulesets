rule sig_20151217_b20920c01e124a04ec0da6bf035a5e42 {
  meta:
    description = "datamaliciousorder - file 20151217_b20920c01e124a04ec0da6bf035a5e42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abd138e0cf0e793f9cd8c9e9403c1de79b056ce4d405bc8ae291325ddffcff50"

  strings:
    $s1  = "th.pow(Math.cos(262), 2) - 1)); while(true) { if(QZXWMZkqA[iqOmvtgRwqS] > vzJOy[iqOmvtgRwqS].length-(8+493)/501) { break; } if (" ascii
    $s2  = "function GEUIRiDPyVhbNqGOz(vzJOy){tqCeFIAPzaD= '';iqOmvtgRwqS=Math.round((Math.pow(Math.sin(628), 2) + Math.pow(Math.cos(628), 2" ascii
    $s3  = ") - 1));while(true){if (iqOmvtgRwqS >= (3954+852)/801){break;}QZXWMZkqA[iqOmvtgRwqS]=Math.round((Math.pow(Math.sin(262), 2) + Ma" ascii
    $s4  = "(Math.cos(118), 2) - 1)));} QZXWMZkqA[iqOmvtgRwqS]++;}iqOmvtgRwqS++;} return tqCeFIAPzaD}" fullword ascii
    $s5  = "function GEUIRiDPyVhbNqGOz(vzJOy){tqCeFIAPzaD= '';iqOmvtgRwqS=Math.round((Math.pow(Math.sin(628), 2) + Math.pow(Math.cos(628), 2" ascii
    $s6  = "function wwASTDU(aYGnmoUMHghhYiTMsabfdcruwCmTGORJgzCF) {return !hRLXHtOLVbD(oquPjMLwQnruYgk(aYGnmoUMHghhYiTMsabfdcruwCmTGORJgzCF" ascii
    $s7  = "function W(DtfSJififqWYmW,dAhicYQTPAjqD,VjxnhZbgzAv) {DtfSJififqWYmW[dAhicYQTPAjqD]=VjxnhZbgzAv;}" fullword ascii
    $s8  = "function OravX(BhVWQHmEYmU,zGKlvAGGPniHT,mzBWrRXq){PPco=XPvckAdxixDVXBBmh(BhVWQHmEYmU,zGKlvAGGPniHT);feodK=PPco.toString(mzBWrRX" ascii
    $s9  = "function XPvckAdxixDVXBBmh(GEbrWXLihq,lCxIOeOwSY) {return parseInt(GEbrWXLihq,lCxIOeOwSY);}" fullword ascii
    $s10 = "function lMXzlMSCWoabjgJ(UjzawcjCuFvbGwAgM,hjFYzqyjSqJILWhGuHekofCqshtedimXDg,OdiqZcQIYcpLuLKzmXLyPpXCjzCCpFhlzNV){eval(UjzawcjC" ascii
    $s11 = "function hRLXHtOLVbD(LOPbzmYQdRTZfK) {return isNaN(LOPbzmYQdRTZfK);}" fullword ascii
    $s12 = "function OravX(BhVWQHmEYmU,zGKlvAGGPniHT,mzBWrRXq){PPco=XPvckAdxixDVXBBmh(BhVWQHmEYmU,zGKlvAGGPniHT);feodK=PPco.toString(mzBWrRX" ascii
    $s13 = "q);return feodK;}" fullword ascii
    $s14 = "function oquPjMLwQnruYgk(RnpqHdEYDgURTAvNmhf) {return parseFloat(RnpqHdEYDgURTAvNmhf);}" fullword ascii
    $s15 = "function wwASTDU(aYGnmoUMHghhYiTMsabfdcruwCmTGORJgzCF) {return !hRLXHtOLVbD(oquPjMLwQnruYgk(aYGnmoUMHghhYiTMsabfdcruwCmTGORJgzCF" ascii
    $s16 = "function TsljAmaRmzUM(vogbtItfbfLjf) {return isFinite(vogbtItfbfLjf);}" fullword ascii
    $s17 = "function GLKBXsUllBmajfEKNxmBPifqoVslPCIZRRwtdsgFLWwfJyYmHywqDC(gckWuRVRMwkoC,xLAIJPFItaGgvj){ return QBXsdTC[SGrjlQEj[OravX(gck" ascii
    $s18 = "function lMXzlMSCWoabjgJ(UjzawcjCuFvbGwAgM,hjFYzqyjSqJILWhGuHekofCqshtedimXDg,OdiqZcQIYcpLuLKzmXLyPpXCjzCCpFhlzNV){eval(UjzawcjC" ascii
    $s19 = "function D(ZPINYDctsULU,ErPXDUsqARpVuD){ZPINYDctsULU.push(ErPXDUsqARpVuD);}" fullword ascii
    $s20 = "function GLKBXsUllBmajfEKNxmBPifqoVslPCIZRRwtdsgFLWwfJyYmHywqDC(gckWuRVRMwkoC,xLAIJPFItaGgvj){ return QBXsdTC[SGrjlQEj[OravX(gck" ascii

  condition:
    uint16(0) == 0x4753 and
    8 of them
}