rule sig_20151217_33481c3ad8cbb2e7779753929b8d8e6e {
  meta:
    description = "datamaliciousorder - file 20151217_33481c3ad8cbb2e7779753929b8d8e6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fffd52416f3172ae6e0477a78699bb00aa4073fcf147a63e338988edb9560de8"

  strings:
    $s1  = "pow(Math.cos(245), 2) - 1)));} XaXwzcpYx[QIWZLavNLKj]++;}QIWZLavNLKj++;} return xuCVuEqqONw}" fullword ascii
    $s2  = "th.pow(Math.cos(374), 2) - 1)); while(true) { if(XaXwzcpYx[QIWZLavNLKj] > AsxlR[QIWZLavNLKj].length-(-295+958)/663) { break; } i" ascii
    $s3  = ") - 1));while(true){if (QIWZLavNLKj >= (3197+973)/695){break;}XaXwzcpYx[QIWZLavNLKj]=Math.round((Math.pow(Math.sin(374), 2) + Ma" ascii
    $s4  = "function uUuHgIPHylKLdoxzp(AsxlR){xuCVuEqqONw= '';QIWZLavNLKj=Math.round((Math.pow(Math.sin(181), 2) + Math.pow(Math.cos(181), 2" ascii
    $s5  = "mUANXoqvYDIFyyLxQoXzhULoHSLjXwZhVBA([AsxlR[QIWZLavNLKj][XaXwzcpYx[QIWZLavNLKj]]], Math.round((Math.pow(Math.sin(245), 2) + Math." ascii
    $s6  = "function uUuHgIPHylKLdoxzp(AsxlR){xuCVuEqqONw= '';QIWZLavNLKj=Math.round((Math.pow(Math.sin(181), 2) + Math.pow(Math.cos(181), 2" ascii
    $s7  = "function jBqOnBB(lsxVAvUmYtzGtRfUrHxxzHTYEQdmgyuuJHuY) {return !RlwNLPQeWSj(soCRIBYPiaTraoo(lsxVAvUmYtzGtRfUrHxxzHTYEQdmgyuuJHuY" ascii
    $s8  = "function TDYiQSctrKoUNJdLdDJmUANXoqvYDIFyyLxQoXzhULoHSLjXwZhVBA(eVGrqzXmXwrgC,LACDaaCVRunddR){ return ewbzlKX[ajwZaozD[mZXMr(eVG" ascii
    $s9  = "function TDYiQSctrKoUNJdLdDJmUANXoqvYDIFyyLxQoXzhULoHSLjXwZhVBA(eVGrqzXmXwrgC,LACDaaCVRunddR){ return ewbzlKX[ajwZaozD[mZXMr(eVG" ascii
    $s10 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s11 = "function B(iNVXgIrsWokZnW,WrVDiCNzPOoLc,sSOdpSefNPf) {iNVXgIrsWokZnW[WrVDiCNzPOoLc]=sSOdpSefNPf;}" fullword ascii
    $s12 = "function soCRIBYPiaTraoo(MdunjzgKKxDSpUUFAau) {return parseFloat(MdunjzgKKxDSpUUFAau);}" fullword ascii
    $s13 = "function cjedhjRlecga(ucmoUnPejIQye) {return isFinite(ucmoUnPejIQye);}" fullword ascii
    $s14 = "function wWlhfaSbwyvxFEP(tTIrTPHeCEggVFBkk,TAzmNnuxtMkFblEtxrDFqcNvUolZPlurAR,XDDrBKDgLJloBTatUDnfmUzboXagXTwQwxa){eval(tTIrTPHe" ascii
    $s15 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s16 = "function RlwNLPQeWSj(jpSWRLEpnrkrxU) {return isNaN(jpSWRLEpnrkrxU);}" fullword ascii
    $s17 = "function mZXMr(xYQtvKCByMz,RFJffBTXCOEJI,uzrtRxse){RHbs=UBfIXHxeGebxnvqwJ(xYQtvKCByMz,RFJffBTXCOEJI);Dwumt=RHbs.toString(uzrtRxs" ascii
    $s18 = "function wWlhfaSbwyvxFEP(tTIrTPHeCEggVFBkk,TAzmNnuxtMkFblEtxrDFqcNvUolZPlurAR,XDDrBKDgLJloBTatUDnfmUzboXagXTwQwxa){eval(tTIrTPHe" ascii
    $s19 = "e);return Dwumt;}" fullword ascii
    $s20 = "function a(IVbIJucPXQJU,HLNsXBPxnjrNCq){IVbIJucPXQJU.push(HLNsXBPxnjrNCq);}" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}