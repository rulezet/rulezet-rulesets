rule sig_20160520_6e1549e09d680d1631507e1f2a1f1553 {
  meta:
    description = "datamaliciousorder - file 20160520_6e1549e09d680d1631507e1f2a1f1553.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "424063937a85e3375fe35eca9a5eaa2772612232d3c687d20828a65f77461a58"

  strings:
    $s1  = "function OahSfMjc(PMfgO) {var EHuBtaLc=OKGlTNNjOSImcWfYwYjgG[2];for(var KVxOI=0;KVxOI<PMfgO;KVxOI++){DvJRL+=EHuBtaLc.charAt(Math" ascii
    $s2  = "function OahSfMjc(PMfgO) {var EHuBtaLc=OKGlTNNjOSImcWfYwYjgG[2];for(var KVxOI=0;KVxOI<PMfgO;KVxOI++){DvJRL+=EHuBtaLc.charAt(Math" ascii
    $s3  = "function NIUYm(wrxEYipL,RfShi,tXPBJYjanK){wrxEYipL.open();wrxEYipL.type = 1;wrxEYipL.write(RfShi);wrxEYipL.position = 0;wrxEYipL" ascii
    $s4  = "function XnIgz(csrasN){return new ActiveXObject(csrasN);}" fullword ascii
    $s5  = "try{dkbtXVT=WxNSJMjNc(qDrsg[aCCo], PZlarHT() + OKGlTNNjOSImcWfYwYjgG[9], 1)}catch(e){}; " fullword ascii
    $s6  = "LkOhA<LPoyrg.length;eGrLkOhA++) {NGthaZt+=XaBHH[LPoyrg[eGrLkOhA]];}return NGthaZt.substring(3,NGthaZt.length);}" fullword ascii
    $s7  = "function NIUYm(wrxEYipL,RfShi,tXPBJYjanK){wrxEYipL.open();wrxEYipL.type = 1;wrxEYipL.write(RfShi);wrxEYipL.position = 0;wrxEYipL" ascii
    $s8  = "function ERKSa(KWnIrezt,LPoyrg,QQgJRMDCD){XaBHH=KWnIrezt.split(QQgJRMDCD);NGthaZt = OKGlTNNjOSImcWfYwYjgG[13];for(eGrLkOhA=0;eGr" ascii
    $s9  = ".floor(Math.random()*EHuBtaLc.length));}return DvJRL;}" fullword ascii
    $s10 = "function WxNSJMjNc(zqUaNIoIb,WHCGFdU,uIhuJCZp){" fullword ascii
    $s11 = "function nlQC(znDpRK,nqOHdyo){KMdP = OKGlTNNjOSImcWfYwYjgG[11].split(OKGlTNNjOSImcWfYwYjgG[12]);nqOHdyo.open(KMdP[0]+KMdP[2]+KMd" ascii
    $s12 = "function PZlarHT() {var IAOv=100000;var sjqwOJ = 100;return Math.random()*(IAOv-sjqwOJ)+sjqwOJ;}" fullword ascii
    $s13 = "P[3], znDpRK, false);nqOHdyo.send();}" fullword ascii
    $s14 = "if (dkbtXVT==0) break;" fullword ascii
    $s15 = "function nlQC(znDpRK,nqOHdyo){KMdP = OKGlTNNjOSImcWfYwYjgG[11].split(OKGlTNNjOSImcWfYwYjgG[12]);nqOHdyo.open(KMdP[0]+KMdP[2]+KMd" ascii
    $s16 = "function gqixkO(csrasN){return csrasN.ExpandEnvironmentStrings(OKGlTNNjOSImcWfYwYjgG[10])}" fullword ascii
    $s17 = "function ERKSa(KWnIrezt,LPoyrg,QQgJRMDCD){XaBHH=KWnIrezt.split(QQgJRMDCD);NGthaZt = OKGlTNNjOSImcWfYwYjgG[13];for(eGrLkOhA=0;eGr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}