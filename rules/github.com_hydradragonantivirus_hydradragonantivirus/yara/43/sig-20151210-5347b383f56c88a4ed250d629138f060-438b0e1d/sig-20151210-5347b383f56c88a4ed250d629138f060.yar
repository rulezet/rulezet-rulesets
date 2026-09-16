rule sig_20151210_5347b383f56c88a4ed250d629138f060 {
  meta:
    description = "datamaliciousorder - file 20151210_5347b383f56c88a4ed250d629138f060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4b50d57f98049e079f3e3678d9ef638dba33bdfb4428dbc4f4d19a74abbb6a5"

  strings:
    $s1  = "function IcLOpoC(ANDEUEUBjrDzbtGqiLrfdnYZtVDsqbRwrMvh) {return !isNaN(parseFloat(ANDEUEUBjrDzbtGqiLrfdnYZtVDsqbRwrMvh)) && isFin" ascii
    $s2  = "function IcLOpoC(ANDEUEUBjrDzbtGqiLrfdnYZtVDsqbRwrMvh) {return !isNaN(parseFloat(ANDEUEUBjrDzbtGqiLrfdnYZtVDsqbRwrMvh)) && isFin" ascii
    $s3  = "qIJNaoG=(-784+784)/379;while(true){if(qIJNaoG>=(19986+494)/160){break;}QrmyOgxxVNJOI[qIJNaoG]=String.fromCharCode(qIJNaoG);qIJNa" ascii
    $s4  = "function ZInGjoaoBfOBlGGuK(tlkCs){fsqtcMYTwBh= '';for(aqLDzrsPAwO=(-863+863)/111; aqLDzrsPAwO < (-745+859)/57; aqLDzrsPAwO++) {s" ascii
    $s5  = "function OMJzB(DwGWCzZaJMJ,ZmnhCnkLUSkyZ,NDZCWGhC){sSBS=parseInt(DwGWCzZaJMJ,ZmnhCnkLUSkyZ);amCYS=sSBS.toString(NDZCWGhC);return" ascii
    $s6  = "function ZInGjoaoBfOBlGGuK(tlkCs){fsqtcMYTwBh= '';for(aqLDzrsPAwO=(-863+863)/111; aqLDzrsPAwO < (-745+859)/57; aqLDzrsPAwO++) {s" ascii
    $s7  = "UCquSLrZ[aqLDzrsPAwO]=(-945+945)/277; while(true) { if(sUCquSLrZ[aqLDzrsPAwO] > tlkCs[aqLDzrsPAwO].length-(632+226)/858) { break" ascii
    $s8  = "qIJNaoG=(-784+784)/379;while(true){if(qIJNaoG>=(19986+494)/160){break;}QrmyOgxxVNJOI[qIJNaoG]=String.fromCharCode(qIJNaoG);qIJNa" ascii
    $s9  = " amCYS;}function lGFKTvZlZgsqBnE(DZEXinhKDhBTyHhkr){eval(DZEXinhKDhBTyHhkr)}" fullword ascii
    $s10 = "function OMJzB(DwGWCzZaJMJ,ZmnhCnkLUSkyZ,NDZCWGhC){sSBS=parseInt(DwGWCzZaJMJ,ZmnhCnkLUSkyZ);amCYS=sSBS.toString(NDZCWGhC);return" ascii
    $s11 = "function TZhDDYPeQHw(XRmxLZOv,twpxuD){return XRmxLZOv.split(twpxuD)}" fullword ascii
    $s12 = "function vJNKUMofCuBPQeaZcVxIvdYWRVVDISUUGCQjzgMfzjkxLqkEvwmzTF(JtNVVoRwDtYzR,RMUPsdocaXhARk){ return QrmyOgxxVNJOI[OMJzB(JtNVVo" ascii
    $s13 = "function vJNKUMofCuBPQeaZcVxIvdYWRVVDISUUGCQjzgMfzjkxLqkEvwmzTF(JtNVVoRwDtYzR,RMUPsdocaXhARk){ return QrmyOgxxVNJOI[OMJzB(JtNVVo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}