rule sig_20151214_73459147e0de8c97d3656c92d74f1aa1 {
  meta:
    description = "datamaliciousorder - file 20151214_73459147e0de8c97d3656c92d74f1aa1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27fb69640c2e295107d0270c17043a89103db0060c1d04ba8465e0d44a02b6db"

  strings:
    $s1  = "ath.pow(Math.cos(774), 2) - 1)); while(true) { if(yCeYgDnQr[oXduCphslwS] > kfTHM[oXduCphslwS].length-(13+781)/794) { break; } if" ascii
    $s2  = "w(Math.cos(341), 2) - 1)));} yCeYgDnQr[oXduCphslwS]++;}} return dUFnTXVKPIa}" fullword ascii
    $s3  = "function TdQsbuPxGieERmwYt(kfTHM){dUFnTXVKPIa= Y[1763];for(oXduCphslwS=Math.round((Math.pow(Math.sin(430), 2) + Math.pow(Math.co" ascii
    $s4  = "function TdQsbuPxGieERmwYt(kfTHM){dUFnTXVKPIa= Y[1763];for(oXduCphslwS=Math.round((Math.pow(Math.sin(430), 2) + Math.pow(Math.co" ascii
    $s5  = "qanw)) {return (String.fromCharCode(JjmzoYbZILhtqanw) + String.fromCharCode((37633+315)/716));}}" fullword ascii
    $s6  = "function Z(HicCXIeEsqMy,cCLUTZXPDjJdDs){HicCXIeEsqMy.push(cCLUTZXPDjJdDs);}function T0(JjmzoYbZILhtqanw){if(GaILeTf(JjmzoYbZILht" ascii
    $s7  = "function GaILeTf(lJTWUGJzxgFHULWTTMJXeXohkVbenFnpQqPt) {return !isNaN(parseFloat(lJTWUGJzxgFHULWTTMJXeXohkVbenFnpQqPt)) && isFin" ascii
    $s8  = "function GaILeTf(lJTWUGJzxgFHULWTTMJXeXohkVbenFnpQqPt) {return !isNaN(parseFloat(lJTWUGJzxgFHULWTTMJXeXohkVbenFnpQqPt)) && isFin" ascii
    $s9  = "function KGktQFwHRsD(fBTHzdBM,NYjdBD){return fBTHzdBM.split(NYjdBD)}" fullword ascii
    $s10 = " DIOzI;}function qKKciBlMKUOlPJA(NYnamxfkovETphxtP,KiYomtktvWiOoOlWoHNiPpCdzcBHEuWAwh,AOvgnEdQvtMlBeQANGZFtEgtncbRyybRrxR){eval(" ascii
    $s11 = "function Z(HicCXIeEsqMy,cCLUTZXPDjJdDs){HicCXIeEsqMy.push(cCLUTZXPDjJdDs);}function T0(JjmzoYbZILhtqanw){if(GaILeTf(JjmzoYbZILht" ascii
    $s12 = "function sqctH(QRkhEytMYwh,AvgMEPmyPZYKr,ZQydknVB){jrZW=parseInt(QRkhEytMYwh,AvgMEPmyPZYKr);DIOzI=jrZW.toString(ZQydknVB);return" ascii
    $s13 = "function qKKciBlMKUOlPJA(NYnamxfkovETphxtP){eval(NYnamxfkovETphxtP)}" fullword ascii
    $s14 = "var Y=new Array();" fullword ascii
    $s15 = "function sqctH(QRkhEytMYwh,AvgMEPmyPZYKr,ZQydknVB){jrZW=parseInt(QRkhEytMYwh,AvgMEPmyPZYKr);DIOzI=jrZW.toString(ZQydknVB);return" ascii
    $s16 = "function rINgfUcAPCAUcVALIubthogIJrTslEFxDUqazcDYqKupgzxCvBOTEM(DaEcAbYKLHjRZ,GycyEqnWZljkkC){ return dKEMgIF[ogCLIpFz[sqctH(DaE" ascii
    $s17 = "function rINgfUcAPCAUcVALIubthogIJrTslEFxDUqazcDYqKupgzxCvBOTEM(DaEcAbYKLHjRZ,GycyEqnWZljkkC){ return dKEMgIF[ogCLIpFz[sqctH(DaE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}