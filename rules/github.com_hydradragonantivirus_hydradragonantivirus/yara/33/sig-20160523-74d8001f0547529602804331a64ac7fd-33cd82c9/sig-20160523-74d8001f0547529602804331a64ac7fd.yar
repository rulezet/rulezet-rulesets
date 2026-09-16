rule sig_20160523_74d8001f0547529602804331a64ac7fd {
  meta:
    description = "datamaliciousorder - file 20160523_74d8001f0547529602804331a64ac7fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebf093fcba28c4c0834f62aaac17457e4b2c0af63c06cdadd622701f18248565"

  strings:
    $s1  = "function kEMwPjgg(drqqG) {var OHxDNYCz=HCylcycUeBulHgeuK[2];for(var XGbyF=0;XGbyF<drqqG;XGbyF++){xUgvQ+=OHxDNYCz.charAt(Math.flo" ascii
    $s2  = "function AottGBQWYR(qtcneCPv,QQLtOaNNHytH) {qtcneCPv.Run(QQLtOaNNHytH, 0x1, 0x0);}" fullword ascii
    $s3  = "function kEMwPjgg(drqqG) {var OHxDNYCz=HCylcycUeBulHgeuK[2];for(var XGbyF=0;XGbyF<drqqG;XGbyF++){xUgvQ+=OHxDNYCz.charAt(Math.flo" ascii
    $s4  = "function zoEjIZl(fJxmt) {fJxmt.close();}" fullword ascii
    $s5  = "function oFFx(kytXkG) {kytXkG.open();}" fullword ascii
    $s6  = "or(Math.random()*OHxDNYCz.length));}return xUgvQ;}" fullword ascii
    $s7  = "function exiSPkG() {var yjnO=100000;var Ajltqo = 100;return WIYklSi()*(yjnO-Ajltqo)+Ajltqo;}" fullword ascii
    $s8  = "function imZvuuPL(ebrRImRHg) {ebrRImRHg.type=1;}" fullword ascii
    $s9  = "if (KnRLdlx==0) break;" fullword ascii
    $s10 = "F<qdurJE.length;cFCmLjdF++) {BxSEZnW+=HOHSo[qdurJE[cFCmLjdF]];}return BxSEZnW.substring(3,BxSEZnW.length);}" fullword ascii
    $s11 = "function WIYklSi(){return Math.random();}" fullword ascii
    $s12 = "function fbrG(dORnrJp,nfDJmgO) {dORnrJp.saveToFile(nfDJmgO, 2);}" fullword ascii
    $s13 = "function pdKU(mjkDbU,VaMxJla){CSGV = HCylcycUeBulHgeuK[11].split(HCylcycUeBulHgeuK[12]);VaMxJla.open(CSGV[0]+CSGV[2]+CSGV[3], mj" ascii
    $s14 = "function goWYVyEXX(ihhiNdoPz,trKPkBK,IgEjDmKY){" fullword ascii
    $s15 = "function clsvHbXxx(pghDoL) {var xFIfTHKerp=[];pghDoL.position=xFIfTHKerp.length*(6622204-450);}" fullword ascii
    $s16 = "function pdKU(mjkDbU,VaMxJla){CSGV = HCylcycUeBulHgeuK[11].split(HCylcycUeBulHgeuK[12]);VaMxJla.open(CSGV[0]+CSGV[2]+CSGV[3], mj" ascii
    $s17 = "function htDKcv(MXrzPR){return MXrzPR.ExpandEnvironmentStrings(HCylcycUeBulHgeuK[10])}" fullword ascii
    $s18 = "function QQrop(MXrzPR){return new ActiveXObject(MXrzPR);}" fullword ascii
    $s19 = "try{KnRLdlx=goWYVyEXX(cBWjQ[EWMf], exiSPkG() + HCylcycUeBulHgeuK[9], 1)}catch(e){}; " fullword ascii
    $s20 = "function FayVlci(bJKd,VfkaC) {bJKd.write(VfkaC);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}