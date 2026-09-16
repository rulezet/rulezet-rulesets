rule sig_20160520_350a289850d989b1044ba91a1d95185f {
  meta:
    description = "datamaliciousorder - file 20160520_350a289850d989b1044ba91a1d95185f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2037c51e0bc23ec28dbc8871c5873f9dc70438108b688332181ccb7bf4c489de"

  strings:
    $s1  = "function sfpIfeSx(qlOVK) {var UCgyWgKs=WmfdATeJmqBAToWusObp[2];for(var JYKCY=0;JYKCY<qlOVK;JYKCY++){eNPiV+=UCgyWgKs.charAt(Math." ascii
    $s2  = "function sfpIfeSx(qlOVK) {var UCgyWgKs=WmfdATeJmqBAToWusObp[2];for(var JYKCY=0;JYKCY<qlOVK;JYKCY++){eNPiV+=UCgyWgKs.charAt(Math." ascii
    $s3  = "function oIgox(VrGDRvfs,PRSbF,DxqGeZwKrd){VrGDRvfs.open();VrGDRvfs.type = 1;VrGDRvfs.write(PRSbF);VrGDRvfs.position = 0;VrGDRvfs" ascii
    $s4  = "Nzkc<YXOvcG.length;IWUtNzkc++) {GAfufIX+=nZPpo[YXOvcG[IWUtNzkc]];}return GAfufIX.substring(3,GAfufIX.length);}" fullword ascii
    $s5  = "function HagXy(CBNPmc){return new ActiveXObject(CBNPmc);}" fullword ascii
    $s6  = "function oIgox(VrGDRvfs,PRSbF,DxqGeZwKrd){VrGDRvfs.open();VrGDRvfs.type = 1;VrGDRvfs.write(PRSbF);VrGDRvfs.position = 0;VrGDRvfs" ascii
    $s7  = "floor(Math.random()*UCgyWgKs.length));}return eNPiV;}" fullword ascii
    $s8  = "function hlPbCR(CBNPmc){return CBNPmc.ExpandEnvironmentStrings(WmfdATeJmqBAToWusObp[10])}" fullword ascii
    $s9  = "function ejQO(zUzKuk,PXaVMgb){vOoJ = WmfdATeJmqBAToWusObp[11].split(WmfdATeJmqBAToWusObp[12]);PXaVMgb.open(vOoJ[0]+vOoJ[2]+vOoJ[" ascii
    $s10 = "function IqtXA(DvFelRcb,YXOvcG,NRijyuDzR){nZPpo=DvFelRcb.split(NRijyuDzR);GAfufIX = WmfdATeJmqBAToWusObp[13];for(IWUtNzkc=0;IWUt" ascii
    $s11 = "function qWGXLer() {var JPPR=100000;var WjQyhW = 100;return Math.random()*(JPPR-WjQyhW)+WjQyhW;}" fullword ascii
    $s12 = "3], zUzKuk, false);PXaVMgb.send();}" fullword ascii
    $s13 = "function ejQO(zUzKuk,PXaVMgb){vOoJ = WmfdATeJmqBAToWusObp[11].split(WmfdATeJmqBAToWusObp[12]);PXaVMgb.open(vOoJ[0]+vOoJ[2]+vOoJ[" ascii
    $s14 = "if (gomqTFj==0) break;" fullword ascii
    $s15 = "function IqtXA(DvFelRcb,YXOvcG,NRijyuDzR){nZPpo=DvFelRcb.split(NRijyuDzR);GAfufIX = WmfdATeJmqBAToWusObp[13];for(IWUtNzkc=0;IWUt" ascii
    $s16 = "try{gomqTFj=RQfdCAdSJ(DBiUL[mtaL], qWGXLer() + WmfdATeJmqBAToWusObp[9], 1)}catch(e){}; " fullword ascii
    $s17 = "function RQfdCAdSJ(czuhZjzfK,IlCpixv,tuBjaDnQ){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}