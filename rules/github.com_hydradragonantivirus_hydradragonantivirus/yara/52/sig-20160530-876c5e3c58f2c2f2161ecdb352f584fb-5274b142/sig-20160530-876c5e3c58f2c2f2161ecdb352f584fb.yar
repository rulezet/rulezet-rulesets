rule sig_20160530_876c5e3c58f2c2f2161ecdb352f584fb {
  meta:
    description = "datamaliciousorder - file 20160530_876c5e3c58f2c2f2161ecdb352f584fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3131722d14a0dbcc65f7bcf649fde799e74d52e072962250ffa507e6aa0ce045"

  strings:
    $s1  = "var CYXMcfuBUGsdh=function(){return WScript.CreateObject(mfsALkUKoRUAOfEvVT[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ezjQCirGSNRGpdxwdwzM(kTAnrYRgPHQGjM,bHJivEEXzmLeUcPZkpD,UbiRCuFYzh){return String.fromCharCode(kTAnrYRgPHQGjM,bHJivEEXz" ascii
    $s3  = "function UzXXj(zlBDRKxILAQ,IqfIjkfXQRLLUMP){return zlBDRKxILAQ.charAt(IqfIjkfXQRLLUMP);}" fullword ascii
    $s4  = "function ezjQCirGSNRGpdxwdwzM(kTAnrYRgPHQGjM,bHJivEEXzmLeUcPZkpD,UbiRCuFYzh){return String.fromCharCode(kTAnrYRgPHQGjM,bHJivEEXz" ascii
    $s5  = "String.fromCharCode(92)+mfsALkUKoRUAOfEvVT[5],true);" fullword ascii
    $s6  = "function ah(HdIDu){return String.fromCharCode(HdIDu);}" fullword ascii
    $s7  = "(lGKfIDwWNuGVjJZnXEdIKNQc == 64) cLJgUQhnxtqhglHSss += ah(cxFnGKeKX);else if (iqfEMibBdjUWIEipSlNHgkfz == 64) cLJgUQhnxtqhglHSss" ascii
    $s8  = "function gnbIXyJ(WECcQaXisAR,dbWul){return String.fromCharCode(WECcQaXisAR,dbWul);}" fullword ascii
    $s9  = "var JABMoOFiHk = ziVhfzhDPLs.createtextfile(CYXMcfuBUGsdh.ExpandEnvironmentStrings(mfsALkUKoRUAOfEvVT[3]+mfsALkUKoRUAOfEvVT[4])+" ascii
    $s10 = "function oGOqNiZRiy(){return XWcvZ(mfsALkUKoRUAOfEvVT[13],[0,3,6],mfsALkUKoRUAOfEvVT[14]);}" fullword ascii
    $s11 = "function pRpJnGcQylxQryp(VphuVRwvKJCQCnefKfYx,cPKBj){return VphuVRwvKJCQCnefKfYx.indexOf(cPKBj);}" fullword ascii
    $s12 = "function DmlMC(){return XWcvZ(mfsALkUKoRUAOfEvVT[11],[2,4,8,10],mfsALkUKoRUAOfEvVT[12]);}" fullword ascii
    $s13 = "function rJbcsMW(pqnadWVEycCop) {var OFwAzjZZTCBxTk = IKZaZ.join(mfsALkUKoRUAOfEvVT[7]);var cxFnGKeKX, RxVbyvpsKtOHEZqelKYzqAG, " ascii
    $s14 = "function rJbcsMW(pqnadWVEycCop) {var OFwAzjZZTCBxTk = IKZaZ.join(mfsALkUKoRUAOfEvVT[7]);var cxFnGKeKX, RxVbyvpsKtOHEZqelKYzqAG, " ascii
    $s15 = "AG, ksPrbmswIMEMsR);} while (QpWZvOvFZmcYqXaWi < pqnadWVEycCop.length);return cLJgUQhnxtqhglHSss;}" fullword ascii
    $s16 = "function kmNFxWZq(meLklY,oKbXJMSU) {var dxaomrIPpLeyHK=[mfsALkUKoRUAOfEvVT[15]];meLklY[dxaomrIPpLeyHK[0]]" fullword ascii
    $s17 = " += gnbIXyJ(cxFnGKeKX, RxVbyvpsKtOHEZqelKYzqAG);else cLJgUQhnxtqhglHSss += ezjQCirGSNRGpdxwdwzM(cxFnGKeKX, RxVbyvpsKtOHEZqelKYzq" ascii
    $s18 = "function XWcvZ(rosIXLSKPTSHB,xOXfdFxEsHDOmF,KCcRRoJWtC){zRHUGnhRoPWH=rosIXLSKPTSHB.split(KCcRRoJWtC);pQirMHAD = mfsALkUKoRUAOfEv" ascii
    $s19 = "function XWcvZ(rosIXLSKPTSHB,xOXfdFxEsHDOmF,KCcRRoJWtC){zRHUGnhRoPWH=rosIXLSKPTSHB.split(KCcRRoJWtC);pQirMHAD = mfsALkUKoRUAOfEv" ascii
    $s20 = "function MQEDqBeR(){return CYXMcfuBUGsdh.ExpandEnvironmentStrings(DSsxJfkErgRC())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}