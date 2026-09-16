rule sig_20151209_47902450224f183e6e71425cec75fe36 {
  meta:
    description = "datamaliciousorder - file 20151209_47902450224f183e6e71425cec75fe36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b29da6339a8fbe472a4d12522bd064665d8577ef1183a9cca461c56869ed0815"

  strings:
    $s1  = "function XdWFqPi(EufHjzPHtijkhWkXRJBZJiAXkTdHylKtyQBY) {return !isNaN(parseFloat(EufHjzPHtijkhWkXRJBZJiAXkTdHylKtyQBY)) && isFin" ascii
    $s2  = "function XdWFqPi(EufHjzPHtijkhWkXRJBZJiAXkTdHylKtyQBY) {return !isNaN(parseFloat(EufHjzPHtijkhWkXRJBZJiAXkTdHylKtyQBY)) && isFin" ascii
    $s3  = "function GQjAI(GJkuDPtyxkZ,lgJoNNGeIhmBw,OnpWOnEL){sWYf=parseInt(GJkuDPtyxkZ,lgJoNNGeIhmBw);fwMoq=sWYf.toString(OnpWOnEL);return" ascii
    $s4  = " fwMoq;}function NRYBgxFchpOAKUh(bLtIyrzLyhoRNFExo){eval(bLtIyrzLyhoRNFExo)}" fullword ascii
    $s5  = "function KrofMwdSJzKiiNNFPaBKemKDCMOmnjVdWHBOYFvbOtJuphCdtYDVOp(rBCdaiyEUheoa,nGanWktThDgCFC){ return dQQiH[GQjAI(rBCdaiyEUheoa[" ascii
    $s6  = "function dIvKiKGofuXiuZEkK(RDrRh){XkEcQaQztlS= '';for(NMpDRBKQcmr=(-165+165)/435; NMpDRBKQcmr < (-272+988)/358; NMpDRBKQcmr++) {" ascii
    $s7  = "LDquxnSpa[NMpDRBKQcmr]=(-184+184)/705; while(true) { if(LDquxnSpa[NMpDRBKQcmr] > RDrRh[NMpDRBKQcmr].length-(186+221)/407) { brea" ascii
    $s8  = "function KrofMwdSJzKiiNNFPaBKemKDCMOmnjVdWHBOYFvbOtJuphCdtYDVOp(rBCdaiyEUheoa,nGanWktThDgCFC){ return dQQiH[GQjAI(rBCdaiyEUheoa[" ascii
    $s9  = "function dIvKiKGofuXiuZEkK(RDrRh){XkEcQaQztlS= '';for(NMpDRBKQcmr=(-165+165)/435; NMpDRBKQcmr < (-272+988)/358; NMpDRBKQcmr++) {" ascii
    $s10 = "function GQjAI(GJkuDPtyxkZ,lgJoNNGeIhmBw,OnpWOnEL){sWYf=parseInt(GJkuDPtyxkZ,lgJoNNGeIhmBw);fwMoq=sWYf.toString(OnpWOnEL);return" ascii
    $s11 = "function IriRHSxWIDz(mvCJBOLC,CdNsJR){return mvCJBOLC.split(CdNsJR)}" fullword ascii
    $s12 = "++;}} return XkEcQaQztlS}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}