rule sig_20151209_8312639368dd86542b65b0ca6ae2e2d8 {
  meta:
    description = "datamaliciousorder - file 20151209_8312639368dd86542b65b0ca6ae2e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22161d79729358dbe17a490311281e93980ce033c5a04a59ffbd7ea72dad920c"

  strings:
    $s1  = "function znTMWJP(pHvyEbvdREBCQqignvtReNmqCTivifLnfBOm) {return !isNaN(parseFloat(pHvyEbvdREBCQqignvtReNmqCTivifLnfBOm)) && isFin" ascii
    $s2  = "function znTMWJP(pHvyEbvdREBCQqignvtReNmqCTivifLnfBOm) {return !isNaN(parseFloat(pHvyEbvdREBCQqignvtReNmqCTivifLnfBOm)) && isFin" ascii
    $s3  = "function elDyU(EOxtstgeocq,MaqBsZFQBcZCN,AxhqXnod){lRsj=parseInt(EOxtstgeocq,MaqBsZFQBcZCN);hLrWf=lRsj.toString(AxhqXnod);return" ascii
    $s4  = "++;}} return BwaffvCrWuE}" fullword ascii
    $s5  = "function sJOzVJALmnDlRUUWJ(mqJxx){BwaffvCrWuE= '';for(bdjmbuNMPER=(-372+372)/197; bdjmbuNMPER < (-439+955)/258; bdjmbuNMPER++) {" ascii
    $s6  = "function AGJvKTuOQks(KRyPmNfe,ByGYgd){return KRyPmNfe.split(ByGYgd)}" fullword ascii
    $s7  = "gaIjtUxIr[bdjmbuNMPER]=(-675+675)/191; while(true) { if(gaIjtUxIr[bdjmbuNMPER] > mqJxx[bdjmbuNMPER].length-(-369+739)/370) { bre" ascii
    $s8  = "function elDyU(EOxtstgeocq,MaqBsZFQBcZCN,AxhqXnod){lRsj=parseInt(EOxtstgeocq,MaqBsZFQBcZCN);hLrWf=lRsj.toString(AxhqXnod);return" ascii
    $s9  = " hLrWf;}function ldiDZXWeBWlIYwK(fRanqktbkvrsbaKOy){eval(fRanqktbkvrsbaKOy)}" fullword ascii
    $s10 = "function sJOzVJALmnDlRUUWJ(mqJxx){BwaffvCrWuE= '';for(bdjmbuNMPER=(-372+372)/197; bdjmbuNMPER < (-439+955)/258; bdjmbuNMPER++) {" ascii
    $s11 = "function RjilEMVURDGLhSznpIHiNwIvfLhcridPacOorqdpgmjQBQWRrvzCLT(JkUuGjpnolYXB,wfsqcaEmtVVOrX){ return Vydxm[elDyU(JkUuGjpnolYXB[" ascii
    $s12 = "function RjilEMVURDGLhSznpIHiNwIvfLhcridPacOorqdpgmjQBQWRrvzCLT(JkUuGjpnolYXB,wfsqcaEmtVVOrX){ return Vydxm[elDyU(JkUuGjpnolYXB[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}