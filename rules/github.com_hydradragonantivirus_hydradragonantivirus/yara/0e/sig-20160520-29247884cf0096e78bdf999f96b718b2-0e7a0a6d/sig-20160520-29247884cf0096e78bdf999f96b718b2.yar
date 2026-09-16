rule sig_20160520_29247884cf0096e78bdf999f96b718b2 {
  meta:
    description = "datamaliciousorder - file 20160520_29247884cf0096e78bdf999f96b718b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4ba156af353eb059c4be51fdbb66dc17c6036bf38376113981b814db7960d60"

  strings:
    $s1  = "function WbmPPhzM(veHnY) {var KIWjraSp=FQOLDZrmud[2];for(var RJHbC=0;RJHbC<veHnY;RJHbC++){htDqr+=KIWjraSp.charAt(Math.floor(Math" ascii
    $s2  = "function WbmPPhzM(veHnY) {var KIWjraSp=FQOLDZrmud[2];for(var RJHbC=0;RJHbC<veHnY;RJHbC++){htDqr+=KIWjraSp.charAt(Math.floor(Math" ascii
    $s3  = "function BBTsHSSFe(PxnzNVbcu,XEfroph,IgZfXjby){" fullword ascii
    $s4  = "function XCfx(xZiTkj,WbXwRZU){HTtN = FQOLDZrmud[11].split(FQOLDZrmud[12]);WbXwRZU.open(HTtN[0]+HTtN[2]+HTtN[3], xZiTkj, false);W" ascii
    $s5  = "function DBSXy(XRRAdSdQ,cMGZHQ,XedXbLbzq){pUwIb=XRRAdSdQ.split(XedXbLbzq);lZANkiw = FQOLDZrmud[13];for(ZNoOzYHV=0;ZNoOzYHV<cMGZH" ascii
    $s6  = "function PUExpbO() {var NVax=100000;var fLdvxq = 100;return Math.random()*(NVax-fLdvxq)+fLdvxq;}" fullword ascii
    $s7  = "function xpvTm(jQSmvGVK,PPGrL,QesaHUzaMi){jQSmvGVK.open();jQSmvGVK.type = 1;jQSmvGVK.write(PPGrL);jQSmvGVK.position = 0;jQSmvGVK" ascii
    $s8  = "function XCfx(xZiTkj,WbXwRZU){HTtN = FQOLDZrmud[11].split(FQOLDZrmud[12]);WbXwRZU.open(HTtN[0]+HTtN[2]+HTtN[3], xZiTkj, false);W" ascii
    $s9  = ".random()*KIWjraSp.length));}return htDqr;}" fullword ascii
    $s10 = "if (Uozwsxy==0) break;" fullword ascii
    $s11 = "function xpvTm(jQSmvGVK,PPGrL,QesaHUzaMi){jQSmvGVK.open();jQSmvGVK.type = 1;jQSmvGVK.write(PPGrL);jQSmvGVK.position = 0;jQSmvGVK" ascii
    $s12 = "function dvMnk(usEmPL){return new ActiveXObject(usEmPL);}" fullword ascii
    $s13 = "Q.length;ZNoOzYHV++) {lZANkiw+=pUwIb[cMGZHQ[ZNoOzYHV]];}return lZANkiw.substring(3,lZANkiw.length);}" fullword ascii
    $s14 = "function ZoRKxV(usEmPL){return usEmPL.ExpandEnvironmentStrings(FQOLDZrmud[10])}" fullword ascii
    $s15 = "function DBSXy(XRRAdSdQ,cMGZHQ,XedXbLbzq){pUwIb=XRRAdSdQ.split(XedXbLbzq);lZANkiw = FQOLDZrmud[13];for(ZNoOzYHV=0;ZNoOzYHV<cMGZH" ascii
    $s16 = "try{Uozwsxy=BBTsHSSFe(BOVzK[nhDD], PUExpbO() + FQOLDZrmud[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}