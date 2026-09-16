rule sig_20151215_617a79ffbd0c573b247ccaf2c3a2b193 {
  meta:
    description = "datamaliciousorder - file 20151215_617a79ffbd0c573b247ccaf2c3a2b193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6231f3421bd2137069b7c49c8f6316f22badd5745f7146345e9ac6fc45b3800"

  strings:
    $s1  = "Math.pow(Math.cos(105), 2) - 1)); while(true) { if(iLywcwyDT[LZubmLeDelq] > Mehpc[LZubmLeDelq].length-(-727+976)/249) { break; }" ascii
    $s2  = "function PuMdvukigMyfpXoMg(Mehpc){DCsfpuHNVPu= A[1773];for(LZubmLeDelq=Math.round((Math.pow(Math.sin(503), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(353), 2) - 1)));} iLywcwyDT[LZubmLeDelq]++;}} return DCsfpuHNVPu}" fullword ascii
    $s4  = "function PuMdvukigMyfpXoMg(Mehpc){DCsfpuHNVPu= A[1773];for(LZubmLeDelq=Math.round((Math.pow(Math.sin(503), 2) + Math.pow(Math.co" ascii
    $s5  = "function y(WfbdmVWIDHOj,DiOBIshymAZBVY){WfbdmVWIDHOj.push(DiOBIshymAZBVY);}function k1(MXoFswrwyhGSVgJL){if(ZwpggIk(MXoFswrwyhGS" ascii
    $s6  = "VgJL)) {return (String.fromCharCode(MXoFswrwyhGSVgJL) + String.fromCharCode((17001+555)/231));}}" fullword ascii
    $s7  = "function ZwpggIk(KNOzGDaUfSFprddAimCGMdtXTnIijyhMFSnf) {return !isNaN(parseFloat(KNOzGDaUfSFprddAimCGMdtXTnIijyhMFSnf)) && isFin" ascii
    $s8  = "function ZwpggIk(KNOzGDaUfSFprddAimCGMdtXTnIijyhMFSnf) {return !isNaN(parseFloat(KNOzGDaUfSFprddAimCGMdtXTnIijyhMFSnf)) && isFin" ascii
    $s9  = "var A=new Array();" fullword ascii
    $s10 = "function y(WfbdmVWIDHOj,DiOBIshymAZBVY){WfbdmVWIDHOj.push(DiOBIshymAZBVY);}function k1(MXoFswrwyhGSVgJL){if(ZwpggIk(MXoFswrwyhGS" ascii
    $s11 = " qmjvJ;}function reZRyZFdWtGNbsN(rhHoewYEVLSMPhMTr,TsXxJvuTmASBVrhPtgwwRIcCBFlUCZnuFU,LTOaefTvxPbGCigyBKFadCikwqOExNPBUaa){eval(" ascii
    $s12 = "function OcBxAPHHwobOPHzsgXnZxOtakFlMQCvnLyZZakwSnuOcwtpfBhaEQB(jFKbCDubzlfvt,ijWfIFqMisDQqE){ return mcvCkVq[zAuKtQkp[loPPl(jFK" ascii
    $s13 = "function reZRyZFdWtGNbsN(rhHoewYEVLSMPhMTr){eval(rhHoewYEVLSMPhMTr)}" fullword ascii
    $s14 = "function OcBxAPHHwobOPHzsgXnZxOtakFlMQCvnLyZZakwSnuOcwtpfBhaEQB(jFKbCDubzlfvt,ijWfIFqMisDQqE){ return mcvCkVq[zAuKtQkp[loPPl(jFK" ascii
    $s15 = "function loPPl(FOqGoxvmjVn,dIkDHFFOGSLZK,kzzZHKsI){CPwy=parseInt(FOqGoxvmjVn,dIkDHFFOGSLZK);qmjvJ=CPwy.toString(kzzZHKsI);return" ascii
    $s16 = "function loPPl(FOqGoxvmjVn,dIkDHFFOGSLZK,kzzZHKsI){CPwy=parseInt(FOqGoxvmjVn,dIkDHFFOGSLZK);qmjvJ=CPwy.toString(kzzZHKsI);return" ascii
    $s17 = "function DKyHJHQJgaS(WvYVrhdH,wOTqps){return WvYVrhdH.split(wOTqps)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}