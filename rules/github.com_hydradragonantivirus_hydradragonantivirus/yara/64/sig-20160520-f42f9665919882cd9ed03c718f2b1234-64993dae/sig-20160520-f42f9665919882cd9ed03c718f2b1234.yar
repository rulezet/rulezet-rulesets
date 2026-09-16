rule sig_20160520_f42f9665919882cd9ed03c718f2b1234 {
  meta:
    description = "datamaliciousorder - file 20160520_f42f9665919882cd9ed03c718f2b1234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2fc3937c3f5e155e583dbd92163ec1731edbc6fda05334bb73a8a10d241b389"

  strings:
    $s1  = "function JDEEDNTj(JEVbY) {var HwxVbIpy=EfMKLuAkkORXnLkwdEtSsz[2];for(var qqWgF=0;qqWgF<JEVbY;qqWgF++){FiSzm+=HwxVbIpy.charAt(Mat" ascii
    $s2  = "function JDEEDNTj(JEVbY) {var HwxVbIpy=EfMKLuAkkORXnLkwdEtSsz[2];for(var qqWgF=0;qqWgF<JEVbY;qqWgF++){FiSzm+=HwxVbIpy.charAt(Mat" ascii
    $s3  = "h.floor(Math.random()*HwxVbIpy.length));}return FiSzm;}" fullword ascii
    $s4  = "try{kwnfnMY=sRXYAClaH(KPFmz[jJAi], iwJllhp() + EfMKLuAkkORXnLkwdEtSsz[9], 1)}catch(e){}; " fullword ascii
    $s5  = "FWM[3], XgeRSb, false);aolQWjb.send();}" fullword ascii
    $s6  = "function YroZPJ(Vsqzvr){return Vsqzvr.ExpandEnvironmentStrings(EfMKLuAkkORXnLkwdEtSsz[10])}" fullword ascii
    $s7  = "function orXQr(DHKeWErB,bBbhW,IISnLDidVE){DHKeWErB.open();DHKeWErB.type = 1;DHKeWErB.write(bBbhW);DHKeWErB.position = 0;DHKeWErB" ascii
    $s8  = "function orXQr(DHKeWErB,bBbhW,IISnLDidVE){DHKeWErB.open();DHKeWErB.type = 1;DHKeWErB.write(bBbhW);DHKeWErB.position = 0;DHKeWErB" ascii
    $s9  = "function llchw(uzCllmIx,HUjxjD,rdORSGUPX){cGotT=uzCllmIx.split(rdORSGUPX);DXYVSoL = EfMKLuAkkORXnLkwdEtSsz[13];for(aBcrBfJm=0;aB" ascii
    $s10 = "function iwJllhp() {var Hpji=100000;var XmCUSu = 100;return Math.random()*(Hpji-XmCUSu)+XmCUSu;}" fullword ascii
    $s11 = "function sRXYAClaH(NJKSWXvgy,byAKuZk,AZBXkqkY){" fullword ascii
    $s12 = "function ARxgR(Vsqzvr){return new ActiveXObject(Vsqzvr);}" fullword ascii
    $s13 = "crBfJm<HUjxjD.length;aBcrBfJm++) {DXYVSoL+=cGotT[HUjxjD[aBcrBfJm]];}return DXYVSoL.substring(3,DXYVSoL.length);}" fullword ascii
    $s14 = "function llchw(uzCllmIx,HUjxjD,rdORSGUPX){cGotT=uzCllmIx.split(rdORSGUPX);DXYVSoL = EfMKLuAkkORXnLkwdEtSsz[13];for(aBcrBfJm=0;aB" ascii
    $s15 = "if (kwnfnMY==0) break;" fullword ascii
    $s16 = "function caXd(XgeRSb,aolQWjb){dFWM = EfMKLuAkkORXnLkwdEtSsz[11].split(EfMKLuAkkORXnLkwdEtSsz[12]);aolQWjb.open(dFWM[0]+dFWM[2]+d" ascii
    $s17 = "function caXd(XgeRSb,aolQWjb){dFWM = EfMKLuAkkORXnLkwdEtSsz[11].split(EfMKLuAkkORXnLkwdEtSsz[12]);aolQWjb.open(dFWM[0]+dFWM[2]+d" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}