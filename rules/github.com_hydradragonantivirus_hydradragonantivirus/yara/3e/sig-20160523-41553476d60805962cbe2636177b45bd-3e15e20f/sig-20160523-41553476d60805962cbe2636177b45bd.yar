rule sig_20160523_41553476d60805962cbe2636177b45bd {
  meta:
    description = "datamaliciousorder - file 20160523_41553476d60805962cbe2636177b45bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9d4b9b0d6318c0a7b1e2089813fd554844b0ccadac3acac28c52af175b8741"

  strings:
    $s1  = "function EpBhKMiiMS(JryZCOeZ,LcqkIosytcXg) {JryZCOeZ.Run(LcqkIosytcXg, 0x1, 0x0);}" fullword ascii
    $s2  = "function eQgTRUsw(Iftkv) {var xQTxuOKE=cfkBvgCvzG[2];for(var UQtkw=0;UQtkw<Iftkv;UQtkw++){dgfXe+=xQTxuOKE.charAt(Math.floor(Math" ascii
    $s3  = "function eQgTRUsw(Iftkv) {var xQTxuOKE=cfkBvgCvzG[2];for(var UQtkw=0;UQtkw<Iftkv;UQtkw++){dgfXe+=xQTxuOKE.charAt(Math.floor(Math" ascii
    $s4  = "try{gVxIKyR=lKtuADLrN(PAeTD[rUep], XDkePvr() + cfkBvgCvzG[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function jswckSyl(TYDZUcjxz) {TYDZUcjxz.type=1;}" fullword ascii
    $s6  = "function QHwNSobun(MYiuys) {var mcxOsGhqMW=[];MYiuys.position=mcxOsGhqMW.length*(1928857-575);}" fullword ascii
    $s7  = "if (gVxIKyR==0) break;" fullword ascii
    $s8  = "m.length;yeQlGsaC++) {lBPlcnu+=NofcC[zRiZym[yeQlGsaC]];}return lBPlcnu.substring(3,lBPlcnu.length);}" fullword ascii
    $s9  = "function CwvEj(DHvMYxMw,zRiZym,OFNHjbJAy){NofcC=DHvMYxMw.split(OFNHjbJAy);lBPlcnu = cfkBvgCvzG[13];for(yeQlGsaC=0;yeQlGsaC<zRiZy" ascii
    $s10 = "function CwvEj(DHvMYxMw,zRiZym,OFNHjbJAy){NofcC=DHvMYxMw.split(OFNHjbJAy);lBPlcnu = cfkBvgCvzG[13];for(yeQlGsaC=0;yeQlGsaC<zRiZy" ascii
    $s11 = ".random()*xQTxuOKE.length));}return dgfXe;}" fullword ascii
    $s12 = "function WFhbanG(){return Math.random();}" fullword ascii
    $s13 = "function DXSXN(KANFyz){return new ActiveXObject(KANFyz);}" fullword ascii
    $s14 = "function AKJr(jHEGzU) {jHEGzU.open();}" fullword ascii
    $s15 = "function eyIj(VffIMK,AsUJaAm){chQe = cfkBvgCvzG[11].split(cfkBvgCvzG[12]);AsUJaAm.open(chQe[0]+chQe[2]+chQe[3], VffIMK, false);A" ascii
    $s16 = "function fMYdG(XlbMROJo,rnOEW,MAAEQEuOFm){AKJr(XlbMROJo);jswckSyl(XlbMROJo);VpktWur(XlbMROJo,rnOEW);QHwNSobun(XlbMROJo);BFfq(Xlb" ascii
    $s17 = "function BFfq(dKJHLkj,mZlPWPq) {dKJHLkj.saveToFile(mZlPWPq, 2);}" fullword ascii
    $s18 = "function fMYdG(XlbMROJo,rnOEW,MAAEQEuOFm){AKJr(XlbMROJo);jswckSyl(XlbMROJo);VpktWur(XlbMROJo,rnOEW);QHwNSobun(XlbMROJo);BFfq(Xlb" ascii
    $s19 = "function QrePLJ(KANFyz){return KANFyz.ExpandEnvironmentStrings(cfkBvgCvzG[10])}" fullword ascii
    $s20 = "function lKtuADLrN(yhrcTPYlg,zsVUEXm,xWMPySjJ){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}