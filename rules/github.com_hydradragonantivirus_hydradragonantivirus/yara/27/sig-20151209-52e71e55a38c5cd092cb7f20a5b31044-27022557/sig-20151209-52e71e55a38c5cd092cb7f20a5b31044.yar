rule sig_20151209_52e71e55a38c5cd092cb7f20a5b31044 {
  meta:
    description = "datamaliciousorder - file 20151209_52e71e55a38c5cd092cb7f20a5b31044.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9390fc8ed5cfd7bab38cf7464c336c53dcb6a1f4991f69cf75d4ef39e633f31"

  strings:
    $s1  = "function VMKViir(tsWRiUxaafZHGFEmofMRaoRkkUvHEXPVkHHQ) {return !isNaN(parseFloat(tsWRiUxaafZHGFEmofMRaoRkkUvHEXPVkHHQ)) && isFin" ascii
    $s2  = "function VMKViir(tsWRiUxaafZHGFEmofMRaoRkkUvHEXPVkHHQ) {return !isNaN(parseFloat(tsWRiUxaafZHGFEmofMRaoRkkUvHEXPVkHHQ)) && isFin" ascii
    $s3  = "function kQmQM(jKXJyWGfIDq,VZGSZbWsNJCWT,qILSFDSE){Ivhp=parseInt(jKXJyWGfIDq,VZGSZbWsNJCWT);XchYA=Ivhp.toString(qILSFDSE);return" ascii
    $s4  = "function kQmQM(jKXJyWGfIDq,VZGSZbWsNJCWT,qILSFDSE){Ivhp=parseInt(jKXJyWGfIDq,VZGSZbWsNJCWT);XchYA=Ivhp.toString(qILSFDSE);return" ascii
    $s5  = ";}} return qLTcXOeAHwO}" fullword ascii
    $s6  = "function jCgpVEuUmFaEddWuN(clMrL){qLTcXOeAHwO= '';for(NowNtgECYCj=(-636+636)/102; NowNtgECYCj < (1388+460)/924; NowNtgECYCj++) {" ascii
    $s7  = "function ViMLEJCelgpqQthusfJvJfEgPYJscFGHQwAAwsHCgTIWeINiNfkiXT(mJvecZZYrEvdk,YeqhJXceqqbSVg){ return NiXiu[kQmQM(mJvecZZYrEvdk[" ascii
    $s8  = "dclJqlrSi[NowNtgECYCj]=(-902+902)/430; while(true) { if(dclJqlrSi[NowNtgECYCj] > clMrL[NowNtgECYCj].length-(-384+847)/463) { bre" ascii
    $s9  = " XchYA;}function FzBVySFzNjuxAKm(yhQsPqeTwQecxhjLo){eval(yhQsPqeTwQecxhjLo)}" fullword ascii
    $s10 = "function dXtzAYTsbIB(YbbwOhMD,skXqIJ){return YbbwOhMD.split(skXqIJ)}" fullword ascii
    $s11 = "function ViMLEJCelgpqQthusfJvJfEgPYJscFGHQwAAwsHCgTIWeINiNfkiXT(mJvecZZYrEvdk,YeqhJXceqqbSVg){ return NiXiu[kQmQM(mJvecZZYrEvdk[" ascii
    $s12 = "function jCgpVEuUmFaEddWuN(clMrL){qLTcXOeAHwO= '';for(NowNtgECYCj=(-636+636)/102; NowNtgECYCj < (1388+460)/924; NowNtgECYCj++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}