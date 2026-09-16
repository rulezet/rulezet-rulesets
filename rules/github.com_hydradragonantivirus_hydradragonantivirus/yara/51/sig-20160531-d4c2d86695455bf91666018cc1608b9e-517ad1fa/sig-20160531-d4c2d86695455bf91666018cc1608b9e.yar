rule sig_20160531_d4c2d86695455bf91666018cc1608b9e {
  meta:
    description = "datamaliciousorder - file 20160531_d4c2d86695455bf91666018cc1608b9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f60b4d03713503fe93c1da191e850840fb244cad8b5346c3cf809ffa2e272233"

  strings:
    $s1  = "var rVDdGO=function(){return WScript.CreateObject(mkxfaMjRmRlVzAPiHHy[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function RNSzCvTdoZy(JXCDAsbNELtzYtJC,dKzdaesmdcIR){return JXCDAsbNELtzYtJC.charAt(dKzdaesmdcIR);}" fullword ascii
    $s3  = "PnDmDLsJy.length);return iDoTg;}" fullword ascii
    $s4  = "(ZUAHhyA,0x1,0x0)}function NxdNZbyJMTj(heYSot,xmzfrGaoh,JhuGvnXPUyeOir){var OtgQF=heYSot.createtextfile(xmzfrGaoh,true);OtgQF.Wr" ascii
    $s5  = "function TjUXZtrf(){return wjQwcCgDCqJjC(mkxfaMjRmRlVzAPiHHy[11],[2,4,8,10],mkxfaMjRmRlVzAPiHHy[12]);}" fullword ascii
    $s6  = "function sxETRFWC(){return rVDdGO.ExpandEnvironmentStrings(AboCrw())}" fullword ascii
    $s7  = "var FjGyuZNhpZLgqX=function(){return new ActiveXObject(mkxfaMjRmRlVzAPiHHy[1]);}();" fullword ascii
    $s8  = "function wjQwcCgDCqJjC(jHUnTB,RClWdNA,watVaEFzBmPW){pmAxuR=jHUnTB.split(watVaEFzBmPW);YbAFSaptTrdGm = mkxfaMjRmRlVzAPiHHy[0];for" ascii
    $s9  = "function AboCrw(){return wjQwcCgDCqJjC(mkxfaMjRmRlVzAPiHHy[9],[1,5,7],mkxfaMjRmRlVzAPiHHy[10]);}" fullword ascii
    $s10 = "function QBSWxXMaBYZViaCLy(uFjicgjfapL,pyCnzCGpsmeIowWE,utVyD){return String.fromCharCode(uFjicgjfapL,pyCnzCGpsmeIowWE,utVyD);}" fullword ascii
    $s11 = "function bUyeLTu(bPCDpVCEnwhm,ZUAHhyA) {var goAIha=[mkxfaMjRmRlVzAPiHHy[15]];bPCDpVCEnwhm[goAIha[0]]" fullword ascii
    $s12 = "Ngio);else iDoTg += QBSWxXMaBYZViaCLy(nipMFu, sZgzKzChZyyuzrUgZINgio, FIyHDOYUbWbIawqs);} while (jBZxtYpfCwoEMMAwFpZfbkOo < QHik" ascii
    $s13 = "function DpDNQis(QRRQNHozYiUCUDCst,YZlFYgogBjJuuBY){return String.fromCharCode(QRRQNHozYiUCUDCst,YZlFYgogBjJuuBY);}" fullword ascii
    $s14 = "(EEgHK=0;EEgHK<RClWdNA.length;EEgHK++) {YbAFSaptTrdGm+=pmAxuR[RClWdNA[EEgHK]];}return YbAFSaptTrdGm.substring(3,YbAFSaptTrdGm.le" ascii
    $s15 = "function BAjZd(QHikPnDmDLsJy) {var AgoyFFhmBWXWarZKPbnuLnkx = AsnujBUBo.join(mkxfaMjRmRlVzAPiHHy[7]);var nipMFu, sZgzKzChZyyuzrU" ascii
    $s16 = "function DkTgTxK(){return wjQwcCgDCqJjC(mkxfaMjRmRlVzAPiHHy[13],[0,3,6],mkxfaMjRmRlVzAPiHHy[14]);}" fullword ascii
    $s17 = "function wjQwcCgDCqJjC(jHUnTB,RClWdNA,watVaEFzBmPW){pmAxuR=jHUnTB.split(watVaEFzBmPW);YbAFSaptTrdGm = mkxfaMjRmRlVzAPiHHy[0];for" ascii
    $s18 = "function watFZrVtYoj(lbpyDqM,LEnTkxXXnv){return lbpyDqM.indexOf(LEnTkxXXnv);}" fullword ascii
    $s19 = "(ZUAHhyA,0x1,0x0)}function NxdNZbyJMTj(heYSot,xmzfrGaoh,JhuGvnXPUyeOir){var OtgQF=heYSot.createtextfile(xmzfrGaoh,true);OtgQF.Wr" ascii
    $s20 = "function qd(KgKrErrJlBehsZxdmiEKvOz){return String.fromCharCode(KgKrErrJlBehsZxdmiEKvOz);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}