rule sig_20160523_b81b55e5e0f998934e8c6cc7e9872611 {
  meta:
    description = "datamaliciousorder - file 20160523_b81b55e5e0f998934e8c6cc7e9872611.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aed0e854871c324406c524e980613fc43b005a604e89cbe7046c93f58bfe1ea"

  strings:
    $s1  = "function MhHPwCsEBh(JgTWmiPt,gThwVbnFKQaQ) {JgTWmiPt.Run(gThwVbnFKQaQ, 0x1, 0x0);}" fullword ascii
    $s2  = "function jNglvWdD(GUPCp) {var MCbvdbsx=lUFMEIcYqduTAJTUja[13];for(var Yxrra=0;Yxrra<GUPCp;Yxrra++){DsDqC+=MCbvdbsx.charAt(Math.f" ascii
    $s3  = "function jNglvWdD(GUPCp) {var MCbvdbsx=lUFMEIcYqduTAJTUja[13];for(var Yxrra=0;Yxrra<GUPCp;Yxrra++){DsDqC+=MCbvdbsx.charAt(Math.f" ascii
    $s4  = "function lpZiE(SkPwSVhg,MjxzAF,wTGopgcQN){btXAi=SkPwSVhg.split(wTGopgcQN);LQFVLau = lUFMEIcYqduTAJTUja[12];for(EnpdfkqU=0;Enpdfk" ascii
    $s5  = "qU<MjxzAF.length;EnpdfkqU++) {LQFVLau+=btXAi[MjxzAF[EnpdfkqU]];}return LQFVLau.substring(3,LQFVLau.length);}" fullword ascii
    $s6  = "loor(Math.random()*MCbvdbsx.length));}return DsDqC;}" fullword ascii
    $s7  = "function OSnlA(ElUyAv){return new ActiveXObject(ElUyAv);}" fullword ascii
    $s8  = "function JwBxWrz() {var uhtT=100000;var nFaNnj = 100;return FadlxCS()*(uhtT-nFaNnj)+nFaNnj;}" fullword ascii
    $s9  = "function WHdi(qwtYaA) {qwtYaA.open();}" fullword ascii
    $s10 = "function uBysBuv(VXLJ,bGeZb) {VXLJ.write(bGeZb);}" fullword ascii
    $s11 = "function RMdfoxgW(dDlkbdZHA) {dDlkbdZHA.type=1;}" fullword ascii
    $s12 = "function dfUsHIn(ieAzD) {ieAzD.close();}" fullword ascii
    $s13 = "function FadlxCS(){return Math.random();}" fullword ascii
    $s14 = "function sCFv(dMFOct,WKocqAl){RXdS = lUFMEIcYqduTAJTUja[10].split(lUFMEIcYqduTAJTUja[11]);WKocqAl.open(RXdS[0]+RXdS[2]+RXdS[3], " ascii
    $s15 = "function UNrwN(yjCgyrQy,RYeMk,TJvGkxyKKM){WHdi(yjCgyrQy);RMdfoxgW(yjCgyrQy);uBysBuv(yjCgyrQy,RYeMk);aDDOdOgFp(yjCgyrQy);APch(yjC" ascii
    $s16 = "function sCFv(dMFOct,WKocqAl){RXdS = lUFMEIcYqduTAJTUja[10].split(lUFMEIcYqduTAJTUja[11]);WKocqAl.open(RXdS[0]+RXdS[2]+RXdS[3], " ascii
    $s17 = "if(xsWq>XzItK.length) break;" fullword ascii
    $s18 = "function UNrwN(yjCgyrQy,RYeMk,TJvGkxyKKM){WHdi(yjCgyrQy);RMdfoxgW(yjCgyrQy);uBysBuv(yjCgyrQy,RYeMk);aDDOdOgFp(yjCgyrQy);APch(yjC" ascii
    $s19 = "function APch(BsEhwVH,DQkAUOx) {BsEhwVH.saveToFile(DQkAUOx, 2);}" fullword ascii
    $s20 = "function aDDOdOgFp(QUsHnD) {var uEktBenchG=[];QUsHnD.position=uEktBenchG.length*(9660437-930);}" fullword ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}