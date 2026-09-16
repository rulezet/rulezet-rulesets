rule sig_20151210_02bc40d3fba2284bcd5d41cc10029668 {
  meta:
    description = "datamaliciousorder - file 20151210_02bc40d3fba2284bcd5d41cc10029668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27bff3b4831ebb298fa82377e09356a0361ea04234fc4fbb1154923673020608"

  strings:
    $s1  = "function CLaUOvv(fcoScnwZrVBWAFdzidHfRVuAkgGIjxwshDvb) {return !isNaN(parseFloat(fcoScnwZrVBWAFdzidHfRVuAkgGIjxwshDvb)) && isFin" ascii
    $s2  = "function CLaUOvv(fcoScnwZrVBWAFdzidHfRVuAkgGIjxwshDvb) {return !isNaN(parseFloat(fcoScnwZrVBWAFdzidHfRVuAkgGIjxwshDvb)) && isFin" ascii
    $s3  = "bRswrtlt[TTBMRGiXMUS]=(-677+677)/117; while(true) { if(SbRswrtlt[TTBMRGiXMUS] > KVzIA[TTBMRGiXMUS].length-(334+228)/562) { break" ascii
    $s4  = " DrGsH;}function mIVfgTxXNLDmWDZ(nkxtBjYAUTQaOFbxd){eval(nkxtBjYAUTQaOFbxd)}" fullword ascii
    $s5  = "bKJmihO=(-95+95)/691;while(true){if(bKJmihO>=(127631+369)/1000){break;}xEpGStBYAKDLz[bKJmihO]=String.fromCharCode(bKJmihO);bKJmi" ascii
    $s6  = "function twZwTUKHhShdajfqBPkfxZNqtYixNjOdPxKQPvYcwtzmZHySMHtJZQ(kAPgRVFySaIeU,nmdPkFeDuSDQgu){ return xEpGStBYAKDLz[PNuqL(kAPgRV" ascii
    $s7  = "function IIMuqWsBppb(ewCwtNwT,ZhGRfC){return ewCwtNwT.split(ZhGRfC)}" fullword ascii
    $s8  = "} return GXjqlHMnxCe}" fullword ascii
    $s9  = "function PNuqL(VGhOoVBtXMx,AoJpdYBFBgVVL,sZOcfUex){VFut=parseInt(VGhOoVBtXMx,AoJpdYBFBgVVL);DrGsH=VFut.toString(sZOcfUex);return" ascii
    $s10 = "function PNuqL(VGhOoVBtXMx,AoJpdYBFBgVVL,sZOcfUex){VFut=parseInt(VGhOoVBtXMx,AoJpdYBFBgVVL);DrGsH=VFut.toString(sZOcfUex);return" ascii
    $s11 = "function twZwTUKHhShdajfqBPkfxZNqtYixNjOdPxKQPvYcwtzmZHySMHtJZQ(kAPgRVFySaIeU,nmdPkFeDuSDQgu){ return xEpGStBYAKDLz[PNuqL(kAPgRV" ascii
    $s12 = "bKJmihO=(-95+95)/691;while(true){if(bKJmihO>=(127631+369)/1000){break;}xEpGStBYAKDLz[bKJmihO]=String.fromCharCode(bKJmihO);bKJmi" ascii
    $s13 = "function hFAgaEExoXlICcABQ(KVzIA){GXjqlHMnxCe= '';for(TTBMRGiXMUS=(-103+103)/353; TTBMRGiXMUS < (1809+91)/950; TTBMRGiXMUS++) {S" ascii
    $s14 = "function hFAgaEExoXlICcABQ(KVzIA){GXjqlHMnxCe= '';for(TTBMRGiXMUS=(-103+103)/353; TTBMRGiXMUS < (1809+91)/950; TTBMRGiXMUS++) {S" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}