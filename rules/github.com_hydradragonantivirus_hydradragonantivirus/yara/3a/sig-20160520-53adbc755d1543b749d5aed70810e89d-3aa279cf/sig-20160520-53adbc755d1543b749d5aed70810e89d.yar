rule sig_20160520_53adbc755d1543b749d5aed70810e89d {
  meta:
    description = "datamaliciousorder - file 20160520_53adbc755d1543b749d5aed70810e89d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "537d97342769c141ee8bb3374b8d7002e3e873669842411ab8c24f16ecfa7972"

  strings:
    $s1  = "function xuiutugy(mdXLO) {var OglkrGDm=QliDyNdGoui[2];for(var fTSeW=0;fTSeW<mdXLO;fTSeW++){UJAig+=OglkrGDm.charAt(Math.floor(Mat" ascii
    $s2  = "function xuiutugy(mdXLO) {var OglkrGDm=QliDyNdGoui[2];for(var fTSeW=0;fTSeW<mdXLO;fTSeW++){UJAig+=OglkrGDm.charAt(Math.floor(Mat" ascii
    $s3  = "function Jllhp(HpjiXmCU,SuJDEE,DNTjJEVbY){qqWgF=HpjiXmCU.split(DNTjJEVbY);FiSzmsf = QliDyNdGoui[13];for(HwxVbIpy=0;HwxVbIpy<SuJD" ascii
    $s4  = "function ViltA(TIFglL){return new ActiveXObject(TIFglL);}" fullword ascii
    $s5  = "try{xudHSnV=QqJFQIipL(zeYBd[mTDn], ivPjrLA() + QliDyNdGoui[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function oJBy(sWfjvn,RLIAJIR){cgfi = QliDyNdGoui[11].split(QliDyNdGoui[12]);RLIAJIR.open(cgfi[0]+cgfi[2]+cgfi[3], sWfjvn, false)" ascii
    $s7  = "function QqJFQIipL(iGeptYKiT,FzaNNmO,FhrXBZFA){" fullword ascii
    $s8  = "if (xudHSnV==0) break;" fullword ascii
    $s9  = "function UrWLKl(TIFglL){return TIFglL.ExpandEnvironmentStrings(QliDyNdGoui[10])}" fullword ascii
    $s10 = "function TwzBk(LfgYjevW,iWwnA,DQKDzGyjHz){LfgYjevW.open();LfgYjevW.type = 1;LfgYjevW.write(iWwnA);LfgYjevW.position = 0;LfgYjevW" ascii
    $s11 = "EE.length;HwxVbIpy++) {FiSzmsf+=qqWgF[SuJDEE[HwxVbIpy]];}return FiSzmsf.substring(3,FiSzmsf.length);}" fullword ascii
    $s12 = "function oJBy(sWfjvn,RLIAJIR){cgfi = QliDyNdGoui[11].split(QliDyNdGoui[12]);RLIAJIR.open(cgfi[0]+cgfi[2]+cgfi[3], sWfjvn, false)" ascii
    $s13 = "function Jllhp(HpjiXmCU,SuJDEE,DNTjJEVbY){qqWgF=HpjiXmCU.split(DNTjJEVbY);FiSzmsf = QliDyNdGoui[13];for(HwxVbIpy=0;HwxVbIpy<SuJD" ascii
    $s14 = "function ivPjrLA() {var rKeC=100000;var zSnlfU = 100;return Math.random()*(rKeC-zSnlfU)+zSnlfU;}" fullword ascii
    $s15 = "function TwzBk(LfgYjevW,iWwnA,DQKDzGyjHz){LfgYjevW.open();LfgYjevW.type = 1;LfgYjevW.write(iWwnA);LfgYjevW.position = 0;LfgYjevW" ascii
    $s16 = "h.random()*OglkrGDm.length));}return UJAig;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}