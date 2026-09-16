rule sig_20160520_8632d05a17f1593a36f01519c5075907 {
  meta:
    description = "datamaliciousorder - file 20160520_8632d05a17f1593a36f01519c5075907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5e0d16480f4912547733ca26ab379f155dce2f6c43c504eded136a385277a3"

  strings:
    $s1  = "function gHgkKukv(nlwwa) {var ZOTJaKRA=aWNYLJ[2];for(var ikTjN=0;ikTjN<nlwwa;ikTjN++){MgWIn+=ZOTJaKRA.charAt(Math.floor(Math.ran" ascii
    $s2  = "function gHgkKukv(nlwwa) {var ZOTJaKRA=aWNYLJ[2];for(var ikTjN=0;ikTjN<nlwwa;ikTjN++){MgWIn+=ZOTJaKRA.charAt(Math.floor(Math.ran" ascii
    $s3  = "function zjGJt(abuIccTk,ooRph,SARIqEinPq){abuIccTk.open();abuIccTk.type = 1;abuIccTk.write(ooRph);abuIccTk.position = 0;abuIccTk" ascii
    $s4  = "try{dbnJxrhbv(KSqHj[jzfK], GNhAhFZ() + aWNYLJ[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function zJJIW(PGmtaLHa,gXyCBN,PmchlPbCR){oIgox=PGmtaLHa.split(PmchlPbCR);VrGDRvf = aWNYLJ[13];for(wqXmRmQB=0;wqXmRmQB<gXyCBN.le" ascii
    $s6  = "function zJJIW(PGmtaLHa,gXyCBN,PmchlPbCR){oIgox=PGmtaLHa.split(PmchlPbCR);VrGDRvf = aWNYLJ[13];for(wqXmRmQB=0;wqXmRmQB<gXyCBN.le" ascii
    $s7  = "function dbnJxrhbv(DJmBznOUo,KHfKsoo,WdIYKinq){" fullword ascii
    $s8  = "dom()*ZOTJaKRA.length));}return MgWIn;}" fullword ascii
    $s9  = "function eVUu(YeIcHO,Lazwiyq){aEiy = aWNYLJ[11].split(aWNYLJ[12]);Lazwiyq.open(aEiy[0]+aEiy[2]+aEiy[3], YeIcHO, false);Lazwiyq.s" ascii
    $s10 = "function eVUu(YeIcHO,Lazwiyq){aEiy = aWNYLJ[11].split(aWNYLJ[12]);Lazwiyq.open(aEiy[0]+aEiy[2]+aEiy[3], YeIcHO, false);Lazwiyq.s" ascii
    $s11 = "function IlCpi(xvtuBj){return new ActiveXObject(xvtuBj);}" fullword ascii
    $s12 = "function aDnQQv(xvtuBj){return xvtuBj.ExpandEnvironmentStrings(aWNYLJ[10])}" fullword ascii
    $s13 = "ngth;wqXmRmQB++) {VrGDRvf+=oIgox[gXyCBN[wqXmRmQB]];}return VrGDRvf.substring(3,VrGDRvf.length);}" fullword ascii
    $s14 = "function GNhAhFZ() {var IbCB=100000;var esQHMK = 100;return Math.random()*(IbCB-esQHMK)+esQHMK;}" fullword ascii
    $s15 = "function zjGJt(abuIccTk,ooRph,SARIqEinPq){abuIccTk.open();abuIccTk.type = 1;abuIccTk.write(ooRph);abuIccTk.position = 0;abuIccTk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}