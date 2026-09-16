rule sig_20151210_47c066d0c18cf30f984e689df4dc9b83 {
  meta:
    description = "datamaliciousorder - file 20151210_47c066d0c18cf30f984e689df4dc9b83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa3aa36d325915b9bee0501c8df02e1939edf42e49c3ef412ce46e18d527997"

  strings:
    $s1  = "function nOOPpkyiTLZjtYNOS(qzEPv){LklsGOkqxUC= '';for(yiCRkluGNrg=(-542+542)/628; yiCRkluGNrg < (662+806)/734; yiCRkluGNrg++) {C" ascii
    $s2  = "function wPvhqKU(YusMGPTaPlzOuLJGKPUGmuYPLTRvTVTcMpqO) {return !isNaN(parseFloat(YusMGPTaPlzOuLJGKPUGmuYPLTRvTVTcMpqO)) && isFin" ascii
    $s3  = "MAComTbT[yiCRkluGNrg]=(-449+449)/479; while(true) { if(CMAComTbT[yiCRkluGNrg] > qzEPv[yiCRkluGNrg].length-(256+512)/768) { break" ascii
    $s4  = "function wPvhqKU(YusMGPTaPlzOuLJGKPUGmuYPLTRvTVTcMpqO) {return !isNaN(parseFloat(YusMGPTaPlzOuLJGKPUGmuYPLTRvTVTcMpqO)) && isFin" ascii
    $s5  = "vASyyqc=(-110+110)/346;while(true){if(vASyyqc>=(46313+663)/367){break;}uytThHfTazTXV[vASyyqc]=String.fromCharCode(vASyyqc);vASyy" ascii
    $s6  = "vASyyqc=(-110+110)/346;while(true){if(vASyyqc>=(46313+663)/367){break;}uytThHfTazTXV[vASyyqc]=String.fromCharCode(vASyyqc);vASyy" ascii
    $s7  = "function HTzAWJvUObrrsLDRqgmuRDYLHzRzFOhUWeeSRfBBSmKRuWteBvHtWx(AvSLgpZIhMKpr,jpllsGJRJxRAiU){ return uytThHfTazTXV[ZDhfd(AvSLgp" ascii
    $s8  = "function HTzAWJvUObrrsLDRqgmuRDYLHzRzFOhUWeeSRfBBSmKRuWteBvHtWx(AvSLgpZIhMKpr,jpllsGJRJxRAiU){ return uytThHfTazTXV[ZDhfd(AvSLgp" ascii
    $s9  = "function ewzBAhckbPd(AcmOjHvk,vHalOR){return AcmOjHvk.split(vHalOR)}" fullword ascii
    $s10 = ";}} return LklsGOkqxUC}" fullword ascii
    $s11 = "function nOOPpkyiTLZjtYNOS(qzEPv){LklsGOkqxUC= '';for(yiCRkluGNrg=(-542+542)/628; yiCRkluGNrg < (662+806)/734; yiCRkluGNrg++) {C" ascii
    $s12 = "function ZDhfd(VPbsTksAAoP,tvlVxyKXnVKNp,eUeqIGlB){KQPF=parseInt(VPbsTksAAoP,tvlVxyKXnVKNp);yQtqf=KQPF.toString(eUeqIGlB);return" ascii
    $s13 = " yQtqf;}function caqqMWZZKEAhwDf(nVbcfWhSecthbsUAU){eval(nVbcfWhSecthbsUAU)}" fullword ascii
    $s14 = "function ZDhfd(VPbsTksAAoP,tvlVxyKXnVKNp,eUeqIGlB){KQPF=parseInt(VPbsTksAAoP,tvlVxyKXnVKNp);yQtqf=KQPF.toString(eUeqIGlB);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}