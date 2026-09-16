rule sig_20160531_38db0ed7f3423b61e4bbdc8de2fbdaaa {
  meta:
    description = "datamaliciousorder - file 20160531_38db0ed7f3423b61e4bbdc8de2fbdaaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc4190f8417c0767ab5abe82fb5f825e4a4fdb07a55de1059e787775450e4776"

  strings:
    $s1  = "var KwMuYZseEqYXq=function(){return WScript.CreateObject(rrOYnu[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function VaYZxBOluiYqGpAxrDcdVEm(yEulWJLwVtPvxPEfXl,eRzbVNkhtiaClPDbSnAK){return yEulWJLwVtPvxPEfXl.charAt(eRzbVNkhtiaClPDbSnAK)" ascii
    $s3  = "function VaYZxBOluiYqGpAxrDcdVEm(yEulWJLwVtPvxPEfXl,eRzbVNkhtiaClPDbSnAK){return yEulWJLwVtPvxPEfXl.charAt(eRzbVNkhtiaClPDbSnAK)" ascii
    $s4  = "(xdmKKPTbMW,0x1,0x0)}function XYxoTUjxF(ncrPRP,ljTUOoN,GWFVSpi){var PJGwzufV=ncrPRP.createtextfile(ljTUOoN,true);PJGwzufV.WriteL" ascii
    $s5  = "el.length);return AYNlGsJUFmJR;}" fullword ascii
    $s6  = "function vy(urMyKJ){return String.fromCharCode(urMyKJ);}" fullword ascii
    $s7  = "function nbbvhxv(kgJFXqX,dpVocGmzNBpcj,UfIIBEff){YZaUWPTL=kgJFXqX.split(UfIIBEff);vDNih = rrOYnu[0];for(oavqecokRrrvd=0;oavqecok" ascii
    $s8  = "function zLYNnqjykT(){return nbbvhxv(rrOYnu[13],[0,3,6],rrOYnu[14]);}" fullword ascii
    $s9  = "function KXqYBJKXkz(EvVNaFSTlvko,xdmKKPTbMW) {var HFtqYESUG=[rrOYnu[15]];EvVNaFSTlvko[HFtqYESUG[0]]" fullword ascii
    $s10 = "function lTEmlWYo(tdkvyHOoToYel) {var EywNzBJzRrbAR = WWlPptvjmKsXSolSNhtOQn.join(rrOYnu[7]);var sWWiyvjfmnRfKieMnmN, NxGPrMrrSe" ascii
    $s11 = "function wBqKfmT(){return nbbvhxv(rrOYnu[11],[2,4,8,10],rrOYnu[12]);}" fullword ascii
    $s12 = "(xdmKKPTbMW,0x1,0x0)}function XYxoTUjxF(ncrPRP,ljTUOoN,GWFVSpi){var PJGwzufV=ncrPRP.createtextfile(ljTUOoN,true);PJGwzufV.WriteL" ascii
    $s13 = "lGsJUFmJR += bCpFrJYJqqzaoMEWpOCeX(sWWiyvjfmnRfKieMnmN, NxGPrMrrSeEgcSxOjO, yDUiNRXSxhuyZNb);} while (iZGAlJRroqdB < tdkvyHOoToY" ascii
    $s14 = "function rDUkuNADtrhtrbOzm(TShdyzQpzjWtRNjtM,vINfrZg){return TShdyzQpzjWtRNjtM.indexOf(vINfrZg);}" fullword ascii
    $s15 = "function XoYglVc(){return nbbvhxv(rrOYnu[9],[1,5,7],rrOYnu[10]);}" fullword ascii
    $s16 = " vy(sWWiyvjfmnRfKieMnmN);else if (CRNarEfn == 64) AYNlGsJUFmJR += NMvLSZaEKubD(sWWiyvjfmnRfKieMnmN, NxGPrMrrSeEgcSxOjO);else AYN" ascii
    $s17 = "function lTEmlWYo(tdkvyHOoToYel) {var EywNzBJzRrbAR = WWlPptvjmKsXSolSNhtOQn.join(rrOYnu[7]);var sWWiyvjfmnRfKieMnmN, NxGPrMrrSe" ascii
    $s18 = "function nbbvhxv(kgJFXqX,dpVocGmzNBpcj,UfIIBEff){YZaUWPTL=kgJFXqX.split(UfIIBEff);vDNih = rrOYnu[0];for(oavqecokRrrvd=0;oavqecok" ascii
    $s19 = "function NMvLSZaEKubD(UQWGneiIgIahm,zzoRoRVZV){return String.fromCharCode(UQWGneiIgIahm,zzoRoRVZV);}" fullword ascii
    $s20 = "Rrrvd<dpVocGmzNBpcj.length;oavqecokRrrvd++) {vDNih+=YZaUWPTL[dpVocGmzNBpcj[oavqecokRrrvd]];}return vDNih.substring(3,vDNih.lengt" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}