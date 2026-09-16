rule sig_20160520_644d7fa9b9c2368ce33643ce0d20f6a2 {
  meta:
    description = "datamaliciousorder - file 20160520_644d7fa9b9c2368ce33643ce0d20f6a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ace012299695d84dc82690c1b985e74f9eaa76aaf1f65eab262413e1dac46d2"

  strings:
    $s1  = "function UoKbQySE(tYKDD) {var tYqSPUIk=KbmtKeKEwWQwezZtwKa[2];for(var QiZdB=0;QiZdB<tYKDD;QiZdB++){agxBh+=tYqSPUIk.charAt(Math.f" ascii
    $s2  = "function UoKbQySE(tYKDD) {var tYqSPUIk=KbmtKeKEwWQwezZtwKa[2];for(var QiZdB=0;QiZdB<tYKDD;QiZdB++){agxBh+=tYqSPUIk.charAt(Math.f" ascii
    $s3  = "function qTKW(DGFxEi,ixALkTU){adlR = KbmtKeKEwWQwezZtwKa[11].split(KbmtKeKEwWQwezZtwKa[12]);ixALkTU.open(adlR[0]+adlR[2]+adlR[3]" ascii
    $s4  = "try{HcnJmMJaa(nymtp[odqu], JVtmMUl() + KbmtKeKEwWQwezZtwKa[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function JVtmMUl() {var NbIa=100000;var gsirbd = 100;return Math.random()*(NbIa-gsirbd)+gsirbd;}" fullword ascii
    $s6  = "function OzEWh(PEqGtruS,WiFTK,VXqtXUokeu){PEqGtruS.open();PEqGtruS.type = 1;PEqGtruS.write(WiFTK);PEqGtruS.position = 0;PEqGtruS" ascii
    $s7  = "function dhVSO(jMGUpa){return new ActiveXObject(jMGUpa);}" fullword ascii
    $s8  = ", DGFxEi, false);ixALkTU.send();}" fullword ascii
    $s9  = "function EtdxdK(jMGUpa){return jMGUpa.ExpandEnvironmentStrings(KbmtKeKEwWQwezZtwKa[10])}" fullword ascii
    $s10 = "function OzEWh(PEqGtruS,WiFTK,VXqtXUokeu){PEqGtruS.open();PEqGtruS.type = 1;PEqGtruS.write(WiFTK);PEqGtruS.position = 0;PEqGtruS" ascii
    $s11 = "function xMXwm(pYsJjKKN,YRRVNG,DgiOnTmzN){zfPac=pYsJjKKN.split(DgiOnTmzN);UaiYsuR = KbmtKeKEwWQwezZtwKa[13];for(gFAvrtbc=0;gFAvr" ascii
    $s12 = "function qTKW(DGFxEi,ixALkTU){adlR = KbmtKeKEwWQwezZtwKa[11].split(KbmtKeKEwWQwezZtwKa[12]);ixALkTU.open(adlR[0]+adlR[2]+adlR[3]" ascii
    $s13 = "function xMXwm(pYsJjKKN,YRRVNG,DgiOnTmzN){zfPac=pYsJjKKN.split(DgiOnTmzN);UaiYsuR = KbmtKeKEwWQwezZtwKa[13];for(gFAvrtbc=0;gFAvr" ascii
    $s14 = "loor(Math.random()*tYqSPUIk.length));}return agxBh;}" fullword ascii
    $s15 = "function HcnJmMJaa(ONBqJFvYt,PvrswMn,EfgeCUNH){" fullword ascii
    $s16 = "tbc<YRRVNG.length;gFAvrtbc++) {UaiYsuR+=zfPac[YRRVNG[gFAvrtbc]];}return UaiYsuR.substring(3,UaiYsuR.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}