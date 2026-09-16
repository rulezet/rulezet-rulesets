rule sig_20151209_977a63e41af996436def3524419e92ed {
  meta:
    description = "datamaliciousorder - file 20151209_977a63e41af996436def3524419e92ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47c90ada9f50e8790f11e8b6f9af69ebeea30a0ee426f353b799c02c2ddc9930"

  strings:
    $s1  = "function pHvKPMl(zBzuSOZtLSZkZTWoeWiadqLmVOEahPlrOEqE) {return !isNaN(parseFloat(zBzuSOZtLSZkZTWoeWiadqLmVOEahPlrOEqE)) && isFin" ascii
    $s2  = "function pHvKPMl(zBzuSOZtLSZkZTWoeWiadqLmVOEahPlrOEqE) {return !isNaN(parseFloat(zBzuSOZtLSZkZTWoeWiadqLmVOEahPlrOEqE)) && isFin" ascii
    $s3  = "function dEVsg(AMsOZvAXzAg,KvcpApQmIYKLR,BSVJnoAx){maop=parseInt(AMsOZvAXzAg,KvcpApQmIYKLR);MHSjt=maop.toString(BSVJnoAx);return" ascii
    $s4  = "function wVKrLWLnfchJpPijhmIMMXpFINaIvsvCqrTPLEaLCDBbLQjjbCpvis(qdkWjaafMGsZY,VgPACTFJeJKNwI){ return uPFvL[dEVsg(qdkWjaafMGsZY[" ascii
    $s5  = " MHSjt;}function XsKPfpwdSyGXlIw(rdsvSpalFcLMYiwex){eval(rdsvSpalFcLMYiwex)}" fullword ascii
    $s6  = "function WHfrOlgIRakryGWhR(ulhfw){mkNcRSlMTWH= '';for(VSlGGuXHyNR=(-820+820)/912; VSlGGuXHyNR < (1052+354)/703; VSlGGuXHyNR++) {" ascii
    $s7  = "++;}} return mkNcRSlMTWH}" fullword ascii
    $s8  = "function wVKrLWLnfchJpPijhmIMMXpFINaIvsvCqrTPLEaLCDBbLQjjbCpvis(qdkWjaafMGsZY,VgPACTFJeJKNwI){ return uPFvL[dEVsg(qdkWjaafMGsZY[" ascii
    $s9  = "function WHfrOlgIRakryGWhR(ulhfw){mkNcRSlMTWH= '';for(VSlGGuXHyNR=(-820+820)/912; VSlGGuXHyNR < (1052+354)/703; VSlGGuXHyNR++) {" ascii
    $s10 = "function dEVsg(AMsOZvAXzAg,KvcpApQmIYKLR,BSVJnoAx){maop=parseInt(AMsOZvAXzAg,KvcpApQmIYKLR);MHSjt=maop.toString(BSVJnoAx);return" ascii
    $s11 = "olcYWwJGe[VSlGGuXHyNR]=(-701+701)/851; while(true) { if(olcYWwJGe[VSlGGuXHyNR] > ulhfw[VSlGGuXHyNR].length-(-89+944)/855) { brea" ascii
    $s12 = "function kqlNlcNPKaj(SIOIWIip,sdCGaG){return SIOIWIip.split(sdCGaG)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}