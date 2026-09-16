rule sig_20160520_f491ec15c09e6ff1600fd36f4f11d322 {
  meta:
    description = "datamaliciousorder - file 20160520_f491ec15c09e6ff1600fd36f4f11d322.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58057ec7b0ad560974333fdb09996b4d9606e1064cb3bfd6f813e1f0b8aca6d8"

  strings:
    $s1  = "function ahNiHFRe(rkMlY) {var VdoTmUyU=VFlahsHeukyEzSpFhtNOr[2];for(var fQAta=0;fQAta<rkMlY;fQAta++){WHiVR+=VdoTmUyU.charAt(Math" ascii
    $s2  = "function ahNiHFRe(rkMlY) {var VdoTmUyU=VFlahsHeukyEzSpFhtNOr[2];for(var fQAta=0;fQAta<rkMlY;fQAta++){WHiVR+=VdoTmUyU.charAt(Math" ascii
    $s3  = "try{zAeTinPKO(iBHrP[ZNtM], sackDLC() + VFlahsHeukyEzSpFhtNOr[9], 1)}catch(e){}; " fullword ascii
    $s4  = "function cKkub(bJkgAXlg,fHhupS,kPchgHQHh){UBLob=bJkgAXlg.split(kPchgHQHh);fVORDoW = VFlahsHeukyEzSpFhtNOr[13];for(PEVWFReM=0;PEV" ascii
    $s5  = "function PQLE(tyNhwu,eSxLWCv){aaEO = VFlahsHeukyEzSpFhtNOr[11].split(VFlahsHeukyEzSpFhtNOr[12]);eSxLWCv.open(aaEO[0]+aaEO[2]+aaE" ascii
    $s6  = "function OnYZaU(PPlHXq){return PPlHXq.ExpandEnvironmentStrings(VFlahsHeukyEzSpFhtNOr[10])}" fullword ascii
    $s7  = "function PQLE(tyNhwu,eSxLWCv){aaEO = VFlahsHeukyEzSpFhtNOr[11].split(VFlahsHeukyEzSpFhtNOr[12]);eSxLWCv.open(aaEO[0]+aaEO[2]+aaE" ascii
    $s8  = "function zAeTinPKO(JtKdgpXmx,BcbYCeH,CqIPBpTL){" fullword ascii
    $s9  = ".floor(Math.random()*VdoTmUyU.length));}return WHiVR;}" fullword ascii
    $s10 = "function FDSGK(PPlHXq){return new ActiveXObject(PPlHXq);}" fullword ascii
    $s11 = "function xwuTH(KybdFrwI,LJwWh,LRPAjbOSoQ){KybdFrwI.open();KybdFrwI.type = 1;KybdFrwI.write(LJwWh);KybdFrwI.position = 0;KybdFrwI" ascii
    $s12 = "function sackDLC() {var XTis=100000;var iAhuuk = 100;return Math.random()*(XTis-iAhuuk)+iAhuuk;}" fullword ascii
    $s13 = "function xwuTH(KybdFrwI,LJwWh,LRPAjbOSoQ){KybdFrwI.open();KybdFrwI.type = 1;KybdFrwI.write(LJwWh);KybdFrwI.position = 0;KybdFrwI" ascii
    $s14 = "function cKkub(bJkgAXlg,fHhupS,kPchgHQHh){UBLob=bJkgAXlg.split(kPchgHQHh);fVORDoW = VFlahsHeukyEzSpFhtNOr[13];for(PEVWFReM=0;PEV" ascii
    $s15 = "O[3], tyNhwu, false);eSxLWCv.send();}" fullword ascii
    $s16 = "WFReM<fHhupS.length;PEVWFReM++) {fVORDoW+=UBLob[fHhupS[PEVWFReM]];}return fVORDoW.substring(3,fVORDoW.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}