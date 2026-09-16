rule sig_20160520_aa942b36f209904078f8d7b9625f096e {
  meta:
    description = "datamaliciousorder - file 20160520_aa942b36f209904078f8d7b9625f096e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6e34a19c1b0a0a877e18087956799554bb56445664c16455b3adaeb1bcf29d"

  strings:
    $s1  = "function OvcGNRij(yuDzR) {var IWUtNzkc=fZbZtFAYtbfKkUIIGMuOI[2];for(var nZPpo=0;nZPpo<yuDzR;nZPpo++){GAfuf+=IWUtNzkc.charAt(Math" ascii
    $s2  = "function OvcGNRij(yuDzR) {var IWUtNzkc=fZbZtFAYtbfKkUIIGMuOI[2];for(var nZPpo=0;nZPpo<yuDzR;nZPpo++){GAfuf+=IWUtNzkc.charAt(Math" ascii
    $s3  = "function kaSPU(ozcIJYzs,lSSqsm,subLLXNui){nncGd=ozcIJYzs.split(subLLXNui);OwCDjZh = fZbZtFAYtbfKkUIIGMuOI[13];for(OyTuoHlH=0;OyT" ascii
    $s4  = "function kaSPU(ozcIJYzs,lSSqsm,subLLXNui){nncGd=ozcIJYzs.split(subLLXNui);OwCDjZh = fZbZtFAYtbfKkUIIGMuOI[13];for(OyTuoHlH=0;OyT" ascii
    $s5  = "function ntZBc(CgDJGQ){return new ActiveXObject(CgDJGQ);}" fullword ascii
    $s6  = "try{RkApzlD=hOObneNuS(EALzl[YGrl], SiIqtXA() + fZbZtFAYtbfKkUIIGMuOI[9], 1)}catch(e){}; " fullword ascii
    $s7  = "x[3], plPgps, false);CBnSRVi.send();}" fullword ascii
    $s8  = ".floor(Math.random()*IWUtNzkc.length));}return GAfuf;}" fullword ascii
    $s9  = "if (RkApzlD==0) break;" fullword ascii
    $s10 = "uoHlH<lSSqsm.length;OyTuoHlH++) {OwCDjZh+=nncGd[lSSqsm[OyTuoHlH]];}return OwCDjZh.substring(3,OwCDjZh.length);}" fullword ascii
    $s11 = "function PuqT(plPgps,CBnSRVi){rrGx = fZbZtFAYtbfKkUIIGMuOI[11].split(fZbZtFAYtbfKkUIIGMuOI[12]);CBnSRVi.open(rrGx[0]+rrGx[2]+rrG" ascii
    $s12 = "function CZEJlq(CgDJGQ){return CgDJGQ.ExpandEnvironmentStrings(fZbZtFAYtbfKkUIIGMuOI[10])}" fullword ascii
    $s13 = "function PuqT(plPgps,CBnSRVi){rrGx = fZbZtFAYtbfKkUIIGMuOI[11].split(fZbZtFAYtbfKkUIIGMuOI[12]);CBnSRVi.open(rrGx[0]+rrGx[2]+rrG" ascii
    $s14 = "function SiIqtXA() {var DvFe=100000;var lRcbYX = 100;return Math.random()*(DvFe-lRcbYX)+lRcbYX;}" fullword ascii
    $s15 = "function hOObneNuS(vauoCSRUC,bggNZri,bJfNKFAg){" fullword ascii
    $s16 = "function UKVsb(hxktmMpV,CAYfi,ZdWKUWRmww){hxktmMpV.open();hxktmMpV.type = 1;hxktmMpV.write(CAYfi);hxktmMpV.position = 0;hxktmMpV" ascii
    $s17 = "function UKVsb(hxktmMpV,CAYfi,ZdWKUWRmww){hxktmMpV.open();hxktmMpV.type = 1;hxktmMpV.write(CAYfi);hxktmMpV.position = 0;hxktmMpV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}