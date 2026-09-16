rule sig_20160520_40cfbb6e9ead03bd0e0c005c7e388faf {
  meta:
    description = "datamaliciousorder - file 20160520_40cfbb6e9ead03bd0e0c005c7e388faf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee9bc9ec70ea8b7052c787e56d313c3cd3c87d21e3e6e731d68f9456cbeb186a"

  strings:
    $s1  = "function UeKTbENC(HgapC) {var HbSeHWvh=MYwaetvUQLZtpkStnYZcV[2];for(var dqKau=0;dqKau<HgapC;dqKau++){oXDFu+=HbSeHWvh.charAt(Math" ascii
    $s2  = "function UeKTbENC(HgapC) {var HbSeHWvh=MYwaetvUQLZtpkStnYZcV[2];for(var dqKau=0;dqKau<HgapC;dqKau++){oXDFu+=HbSeHWvh.charAt(Math" ascii
    $s3  = "n[3], tWJJMe, false);aBXZLNY.send();}" fullword ascii
    $s4  = "function vhIGW(AejVVLPj,qglgju,IBziQOKzW){yXqJA=AejVVLPj.split(IBziQOKzW);xSPELWx = MYwaetvUQLZtpkStnYZcV[13];for(LOZLIkLv=0;LOZ" ascii
    $s5  = "try{IEaZdmHhp(ljBgE[hkJP], zBAddoD() + MYwaetvUQLZtpkStnYZcV[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function BLTLb(kYbGJJXo,NNRyB,wBhEtsPbRj){kYbGJJXo.open();kYbGJJXo.type = 1;kYbGJJXo.write(NNRyB);kYbGJJXo.position = 0;kYbGJJXo" ascii
    $s7  = "function zBAddoD() {var oGfP=100000;var quShNd = 100;return Math.random()*(oGfP-quShNd)+quShNd;}" fullword ascii
    $s8  = "function BLTLb(kYbGJJXo,NNRyB,wBhEtsPbRj){kYbGJJXo.open();kYbGJJXo.type = 1;kYbGJJXo.write(NNRyB);kYbGJJXo.position = 0;kYbGJJXo" ascii
    $s9  = "function uxCr(tWJJMe,aBXZLNY){mBJn = MYwaetvUQLZtpkStnYZcV[11].split(MYwaetvUQLZtpkStnYZcV[12]);aBXZLNY.open(mBJn[0]+mBJn[2]+mBJ" ascii
    $s10 = ".floor(Math.random()*HbSeHWvh.length));}return oXDFu;}" fullword ascii
    $s11 = "LIkLv<qglgju.length;LOZLIkLv++) {xSPELWx+=yXqJA[qglgju[LOZLIkLv]];}return xSPELWx.substring(3,xSPELWx.length);}" fullword ascii
    $s12 = "function IEaZdmHhp(WcSebHjGt,wMIpTGt,HWvBNfkq){" fullword ascii
    $s13 = "function uxCr(tWJJMe,aBXZLNY){mBJn = MYwaetvUQLZtpkStnYZcV[11].split(MYwaetvUQLZtpkStnYZcV[12]);aBXZLNY.open(mBJn[0]+mBJn[2]+mBJ" ascii
    $s14 = "function vhIGW(AejVVLPj,qglgju,IBziQOKzW){yXqJA=AejVVLPj.split(IBziQOKzW);xSPELWx = MYwaetvUQLZtpkStnYZcV[13];for(LOZLIkLv=0;LOZ" ascii
    $s15 = "function UjMBB(yITtCA){return new ActiveXObject(yITtCA);}" fullword ascii
    $s16 = "function cntUOC(yITtCA){return yITtCA.ExpandEnvironmentStrings(MYwaetvUQLZtpkStnYZcV[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}