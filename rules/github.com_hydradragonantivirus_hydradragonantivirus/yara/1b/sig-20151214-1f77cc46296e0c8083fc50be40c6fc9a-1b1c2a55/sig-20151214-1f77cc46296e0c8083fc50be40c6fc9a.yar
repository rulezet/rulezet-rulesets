rule sig_20151214_1f77cc46296e0c8083fc50be40c6fc9a {
  meta:
    description = "datamaliciousorder - file 20151214_1f77cc46296e0c8083fc50be40c6fc9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac2a3606b5e0f8df58ca01b0c59d14a8c54848e168d4112b8dc9fabd45b2c72"

  strings:
    $s1  = "Math.cos(725), 2) - 1)));} idJBoenId[QOKhMFqeJOp]++;}} return YBvpLtsRnxo}" fullword ascii
    $s2  = "function qdkuMiKbZPxCBUeFN(zkHqN){YBvpLtsRnxo= s[1767];for(QOKhMFqeJOp=Math.round((Math.pow(Math.sin(334), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(58), 2) - 1)); while(true) { if(idJBoenId[QOKhMFqeJOp] > zkHqN[QOKhMFqeJOp].length-(139+249)/388) { break; } if (" ascii
    $s4  = "function qdkuMiKbZPxCBUeFN(zkHqN){YBvpLtsRnxo= s[1767];for(QOKhMFqeJOp=Math.round((Math.pow(Math.sin(334), 2) + Math.pow(Math.co" ascii
    $s5  = "function y(QNOaAYlWXFds,TMYKdUxMKmcSWU){QNOaAYlWXFds.push(TMYKdUxMKmcSWU);}function Z3(NOETTexapyhLfRlN){if(HdZBLrg(NOETTexapyhL" ascii
    $s6  = "fRlN)) {return (String.fromCharCode(NOETTexapyhLfRlN) + String.fromCharCode((48940+485)/659));}}" fullword ascii
    $s7  = "function ExsyElHlDBcoMACKFbwEppekoxGnYnAsmOPkngAVrDNnmIihmMaFYK(PmjdLgAgnypqL,ROoNBnIjuVaBLH){ return tnwpgHY[GoJKiNVj[uwSBO(Pmj" ascii
    $s8  = "function HdZBLrg(NBGwxDsZNldTAfdrtfHwrQDuhxDCCpMSPqgJ) {return !isNaN(parseFloat(NBGwxDsZNldTAfdrtfHwrQDuhxDCCpMSPqgJ)) && isFin" ascii
    $s9  = "function HdZBLrg(NBGwxDsZNldTAfdrtfHwrQDuhxDCCpMSPqgJ) {return !isNaN(parseFloat(NBGwxDsZNldTAfdrtfHwrQDuhxDCCpMSPqgJ)) && isFin" ascii
    $s10 = "function ExsyElHlDBcoMACKFbwEppekoxGnYnAsmOPkngAVrDNnmIihmMaFYK(PmjdLgAgnypqL,ROoNBnIjuVaBLH){ return tnwpgHY[GoJKiNVj[uwSBO(Pmj" ascii
    $s11 = "function EANehZAHfptTZXm(CvZEqrTEJPbvlrlHw){eval(CvZEqrTEJPbvlrlHw)}" fullword ascii
    $s12 = "function HfjnoPmSUBJ(SpVPQvYe,yovXyg){return SpVPQvYe.split(yovXyg)}" fullword ascii
    $s13 = "var s=new Array();" fullword ascii
    $s14 = "function uwSBO(gLugHrSnpMV,eCEqkQVDjKtPr,tCBYvaYT){LIhU=parseInt(gLugHrSnpMV,eCEqkQVDjKtPr);KOBtR=LIhU.toString(tCBYvaYT);return" ascii
    $s15 = "function uwSBO(gLugHrSnpMV,eCEqkQVDjKtPr,tCBYvaYT){LIhU=parseInt(gLugHrSnpMV,eCEqkQVDjKtPr);KOBtR=LIhU.toString(tCBYvaYT);return" ascii
    $s16 = " KOBtR;}function EANehZAHfptTZXm(CvZEqrTEJPbvlrlHw,ywZcqDGTwfCifCCSGYpMZPKTOTITKMVgwb,SciCMbyIatctUfhNbAUvQbZIVeaTDnIoTSH){eval(" ascii
    $s17 = "function y(QNOaAYlWXFds,TMYKdUxMKmcSWU){QNOaAYlWXFds.push(TMYKdUxMKmcSWU);}function Z3(NOETTexapyhLfRlN){if(HdZBLrg(NOETTexapyhL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}