rule sig_20160520_625ba415a263537fc7e465f5b4c49e96 {
  meta:
    description = "datamaliciousorder - file 20160520_625ba415a263537fc7e465f5b4c49e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c2feb45453189e144eb2f1e7ffb0f2a13c989d1a804aedc40ea1eafe21a7cdf"

  strings:
    $s1  = "function bxuSxfbb(JQvLx) {var VadamPGb=XGCKoyBI[2];for(var inzNB=0;inzNB<JQvLx;inzNB++){qoVHy+=VadamPGb.charAt(Math.floor(Math.r" ascii
    $s2  = "function bxuSxfbb(JQvLx) {var VadamPGb=XGCKoyBI[2];for(var inzNB=0;inzNB<JQvLx;inzNB++){qoVHy+=VadamPGb.charAt(Math.floor(Math.r" ascii
    $s3  = "function eGrfV(DGQccjCm,wwvJC,tZgNyuNTKl){DGQccjCm.open();DGQccjCm.type = 1;DGQccjCm.write(wwvJC);DGQccjCm.position = 0;DGQccjCm" ascii
    $s4  = "try{DlUJfSc=yRewCCEJW(aVlYa[HhLR], QOawkeU() + XGCKoyBI[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function vPuBy(NmjVld){return new ActiveXObject(NmjVld);}" fullword ascii
    $s6  = "function yRewCCEJW(vSRFkdYBI,xHpTlJT,xfwLxpLR){" fullword ascii
    $s7  = "function poAC(ZPUYCO,pEjdKZE){ZDob = XGCKoyBI[11].split(XGCKoyBI[12]);pEjdKZE.open(ZDob[0]+ZDob[2]+ZDob[3], ZPUYCO, false);pEjdK" ascii
    $s8  = "function eGrfV(DGQccjCm,wwvJC,tZgNyuNTKl){DGQccjCm.open();DGQccjCm.type = 1;DGQccjCm.write(wwvJC);DGQccjCm.position = 0;DGQccjCm" ascii
    $s9  = "length;Pxsmnclt++) {rnymYFV+=aWmxh[hXCKNI[Pxsmnclt]];}return rnymYFV.substring(3,rnymYFV.length);}" fullword ascii
    $s10 = "andom()*VadamPGb.length));}return qoVHy;}" fullword ascii
    $s11 = "if (DlUJfSc==0) break;" fullword ascii
    $s12 = "function MjxeQ(RWDBmHmx,hXCKNI,zTOiBbwoG){aWmxh=RWDBmHmx.split(zTOiBbwoG);rnymYFV = XGCKoyBI[13];for(Pxsmnclt=0;Pxsmnclt<hXCKNI." ascii
    $s13 = "function NrVlNQ(NmjVld){return NmjVld.ExpandEnvironmentStrings(XGCKoyBI[10])}" fullword ascii
    $s14 = "function MjxeQ(RWDBmHmx,hXCKNI,zTOiBbwoG){aWmxh=RWDBmHmx.split(zTOiBbwoG);rnymYFV = XGCKoyBI[13];for(Pxsmnclt=0;Pxsmnclt<hXCKNI." ascii
    $s15 = "function poAC(ZPUYCO,pEjdKZE){ZDob = XGCKoyBI[11].split(XGCKoyBI[12]);pEjdKZE.open(ZDob[0]+ZDob[2]+ZDob[3], ZPUYCO, false);pEjdK" ascii
    $s16 = "function QOawkeU() {var Oiqw=100000;var ZomaBH = 100;return Math.random()*(Oiqw-ZomaBH)+ZomaBH;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}