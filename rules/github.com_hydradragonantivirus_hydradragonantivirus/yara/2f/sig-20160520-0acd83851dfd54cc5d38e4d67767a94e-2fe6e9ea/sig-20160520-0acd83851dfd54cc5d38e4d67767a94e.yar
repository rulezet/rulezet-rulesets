rule sig_20160520_0acd83851dfd54cc5d38e4d67767a94e {
  meta:
    description = "datamaliciousorder - file 20160520_0acd83851dfd54cc5d38e4d67767a94e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fd7e8091dea28c0f48b09154c01f6cc84d29bb27e1df95266df02bb0407d5bb"

  strings:
    $s1  = "function hdlskcDW(dItvW) {var NGsBKNTe=JHFcwgB[2];for(var qOCqX=0;qOCqX<dItvW;qOCqX++){hzwxQ+=NGsBKNTe.charAt(Math.floor(Math.ra" ascii
    $s2  = "function hdlskcDW(dItvW) {var NGsBKNTe=JHFcwgB[2];for(var qOCqX=0;qOCqX<dItvW;qOCqX++){hzwxQ+=NGsBKNTe.charAt(Math.floor(Math.ra" ascii
    $s3  = "function zGNB(GGTOdj,leDGpAr){PcId = JHFcwgB[11].split(JHFcwgB[12]);leDGpAr.open(PcId[0]+PcId[2]+PcId[3], GGTOdj, false);leDGpAr" ascii
    $s4  = "if (HAzoZzM==0) break;" fullword ascii
    $s5  = "ength;KkEhsigw++) {fncWbcP+=GUUVf[eyYhjy[KkEhsigw]];}return fncWbcP.substring(3,fncWbcP.length);}" fullword ascii
    $s6  = "ndom()*NGsBKNTe.length));}return hzwxQ;}" fullword ascii
    $s7  = "function bwJWT(jickHyde,eyYhjy,kxjsMFOxd){GUUVf=jickHyde.split(kxjsMFOxd);fncWbcP = JHFcwgB[13];for(KkEhsigw=0;KkEhsigw<eyYhjy.l" ascii
    $s8  = "function QXpIvbf() {var Qvbk=100000;var DWhvUC = 100;return Math.random()*(Qvbk-DWhvUC)+DWhvUC;}" fullword ascii
    $s9  = "function pyFIU(okKKCt){return new ActiveXObject(okKKCt);}" fullword ascii
    $s10 = "function ZKWynPfTi(LbUGdzeEv,EUGtcHj,bdkmYuVn){" fullword ascii
    $s11 = "function uQBYKS(okKKCt){return okKKCt.ExpandEnvironmentStrings(JHFcwgB[10])}" fullword ascii
    $s12 = "function bwJWT(jickHyde,eyYhjy,kxjsMFOxd){GUUVf=jickHyde.split(kxjsMFOxd);fncWbcP = JHFcwgB[13];for(KkEhsigw=0;KkEhsigw<eyYhjy.l" ascii
    $s13 = "try{HAzoZzM=ZKWynPfTi(MceuG[sxnP], QXpIvbf() + JHFcwgB[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function zGNB(GGTOdj,leDGpAr){PcId = JHFcwgB[11].split(JHFcwgB[12]);leDGpAr.open(PcId[0]+PcId[2]+PcId[3], GGTOdj, false);leDGpAr" ascii
    $s15 = "function soETq(beAEWCAs,QWztb,MBRwVmysWK){beAEWCAs.open();beAEWCAs.type = 1;beAEWCAs.write(QWztb);beAEWCAs.position = 0;beAEWCAs" ascii
    $s16 = "function soETq(beAEWCAs,QWztb,MBRwVmysWK){beAEWCAs.open();beAEWCAs.type = 1;beAEWCAs.write(QWztb);beAEWCAs.position = 0;beAEWCAs" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}