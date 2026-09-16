rule sig_20160520_e77dd225aa2e9df2461729145f47caa0 {
  meta:
    description = "datamaliciousorder - file 20160520_e77dd225aa2e9df2461729145f47caa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3e07a884f4d8657b2747b5950f88b903a364ccf48d3bce074e3b1f0f82a023f"

  strings:
    $s1  = "function XkldN(LGZmgiEN,SZehUH,jLLmftptD){CKxWR=LGZmgiEN.split(jLLmftptD);XJNUpVm = QHiWQ[13];for(vehPJdhA=0;vehPJdhA<SZehUH.len" ascii
    $s2  = "function LYyWbXRC(OuXZv) {var vZfWELmP=QHiWQ[2];for(var brmYp=0;brmYp<OuXZv;brmYp++){DxVBF+=vZfWELmP.charAt(Math.floor(Math.rand" ascii
    $s3  = "function LYyWbXRC(OuXZv) {var vZfWELmP=QHiWQ[2];for(var brmYp=0;brmYp<OuXZv;brmYp++){DxVBF+=vZfWELmP.charAt(Math.floor(Math.rand" ascii
    $s4  = "function XkldN(LGZmgiEN,SZehUH,jLLmftptD){CKxWR=LGZmgiEN.split(jLLmftptD);XJNUpVm = QHiWQ[13];for(vehPJdhA=0;vehPJdhA<SZehUH.len" ascii
    $s5  = "function BqYX(tfYUXb,mElJzsG){iWci = QHiWQ[11].split(QHiWQ[12]);mElJzsG.open(iWci[0]+iWci[2]+iWci[3], tfYUXb, false);mElJzsG.sen" ascii
    $s6  = "om()*vZfWELmP.length));}return DxVBF;}" fullword ascii
    $s7  = "function UYxwzmy() {var cjcD=100000;var CsUTfQ = 100;return Math.random()*(cjcD-CsUTfQ)+CsUTfQ;}" fullword ascii
    $s8  = "function tBJCoHquN(tmXzIOvxW,RCZZuZQ,kVQhutFL){" fullword ascii
    $s9  = "function mBZkk(coEeBOqu,dMldo,TGEmuvVCbV){coEeBOqu.open();coEeBOqu.type = 1;coEeBOqu.write(dMldo);coEeBOqu.position = 0;coEeBOqu" ascii
    $s10 = "function BqYX(tfYUXb,mElJzsG){iWci = QHiWQ[11].split(QHiWQ[12]);mElJzsG.open(iWci[0]+iWci[2]+iWci[3], tfYUXb, false);mElJzsG.sen" ascii
    $s11 = "gth;vehPJdhA++) {XJNUpVm+=CKxWR[SZehUH[vehPJdhA]];}return XJNUpVm.substring(3,XJNUpVm.length);}" fullword ascii
    $s12 = "function ZSLXI(cswNSU){return new ActiveXObject(cswNSU);}" fullword ascii
    $s13 = "function rGOwSg(cswNSU){return cswNSU.ExpandEnvironmentStrings(QHiWQ[10])}" fullword ascii
    $s14 = "function mBZkk(coEeBOqu,dMldo,TGEmuvVCbV){coEeBOqu.open();coEeBOqu.type = 1;coEeBOqu.write(dMldo);coEeBOqu.position = 0;coEeBOqu" ascii
    $s15 = "if (umWJOfU==0) break;" fullword ascii
    $s16 = "try{umWJOfU=tBJCoHquN(sDqXW[Uqvj], UYxwzmy() + QHiWQ[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}