rule sig_20160520_150a04d396c2a1b2e9ae2e0f6f905875 {
  meta:
    description = "datamaliciousorder - file 20160520_150a04d396c2a1b2e9ae2e0f6f905875.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63506b27d36e6e4feb63a1ec966d06a20323a6f18455e30c1516c0e957288f14"

  strings:
    $s1  = "function FbjSPZba(jTZEy) {var bDIVpJRl=XpFOMrCtn[2];for(var aRkEc=0;aRkEc<jTZEy;aRkEc++){ZsNLF+=bDIVpJRl.charAt(Math.floor(Math." ascii
    $s2  = "function FbjSPZba(jTZEy) {var bDIVpJRl=XpFOMrCtn[2];for(var aRkEc=0;aRkEc<jTZEy;aRkEc++){ZsNLF+=bDIVpJRl.charAt(Math.floor(Math." ascii
    $s3  = "function UTUGYMDxl(dMFtsEwuj,aIGGigb,qQjfqiIP){" fullword ascii
    $s4  = "function PRmMt(dNvILTat,ifGLl,uRwlkLLbAV){dNvILTat.open();dNvILTat.type = 1;dNvILTat.write(ifGLl);dNvILTat.position = 0;dNvILTat" ascii
    $s5  = "random()*bDIVpJRl.length));}return ZsNLF;}" fullword ascii
    $s6  = "try{ooGLKRg=UTUGYMDxl(vqCht[QWoO], YafgYEP() + XpFOMrCtn[9], 1)}catch(e){}; " fullword ascii
    $s7  = "if (ooGLKRg==0) break;" fullword ascii
    $s8  = "function pZOz(tWZbKl,FGyJEVw){IwWN = XpFOMrCtn[11].split(XpFOMrCtn[12]);FGyJEVw.open(IwWN[0]+IwWN[2]+IwWN[3], tWZbKl, false);FGy" ascii
    $s9  = "function liaji(rCGFIjGi,RpHVeK,JwgMiSkpf){PhPJI=rCGFIjGi.split(JwgMiSkpf);xMcusUj = XpFOMrCtn[13];for(MZIWjLLH=0;MZIWjLLH<RpHVeK" ascii
    $s10 = "function liaji(rCGFIjGi,RpHVeK,JwgMiSkpf){PhPJI=rCGFIjGi.split(JwgMiSkpf);xMcusUj = XpFOMrCtn[13];for(MZIWjLLH=0;MZIWjLLH<RpHVeK" ascii
    $s11 = "function PRmMt(dNvILTat,ifGLl,uRwlkLLbAV){dNvILTat.open();dNvILTat.type = 1;dNvILTat.write(ifGLl);dNvILTat.position = 0;dNvILTat" ascii
    $s12 = ".length;MZIWjLLH++) {xMcusUj+=PhPJI[RpHVeK[MZIWjLLH]];}return xMcusUj.substring(3,xMcusUj.length);}" fullword ascii
    $s13 = "function ELCNoK(kbIKDP){return kbIKDP.ExpandEnvironmentStrings(XpFOMrCtn[10])}" fullword ascii
    $s14 = "function YafgYEP() {var jvyb=100000;var yUvizA = 100;return Math.random()*(jvyb-yUvizA)+yUvizA;}" fullword ascii
    $s15 = "function pZOz(tWZbKl,FGyJEVw){IwWN = XpFOMrCtn[11].split(XpFOMrCtn[12]);FGyJEVw.open(IwWN[0]+IwWN[2]+IwWN[3], tWZbKl, false);FGy" ascii
    $s16 = "function EMhcA(kbIKDP){return new ActiveXObject(kbIKDP);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}