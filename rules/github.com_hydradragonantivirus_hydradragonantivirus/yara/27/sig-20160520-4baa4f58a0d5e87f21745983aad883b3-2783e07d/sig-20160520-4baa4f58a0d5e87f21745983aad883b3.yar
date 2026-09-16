rule sig_20160520_4baa4f58a0d5e87f21745983aad883b3 {
  meta:
    description = "datamaliciousorder - file 20160520_4baa4f58a0d5e87f21745983aad883b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89076d8168d8f4950ad0773f8a6177aa1e63870531cda1fef17c0512c1470153"

  strings:
    $s1  = "function guJioASX(dndrk) {var XQwWxdPX=JzepKioCJokAFrczM[2];for(var foCyM=0;foCyM<dndrk;foCyM++){womKY+=XQwWxdPX.charAt(Math.flo" ascii
    $s2  = "function guJioASX(dndrk) {var XQwWxdPX=JzepKioCJokAFrczM[2];for(var foCyM=0;foCyM<dndrk;foCyM++){womKY+=XQwWxdPX.charAt(Math.flo" ascii
    $s3  = "try{CQBINFCmq(NMQZu[pegJ], UcJPFRO() + JzepKioCJokAFrczM[9], 1)}catch(e){}; " fullword ascii
    $s4  = "function CQBINFCmq(ypfrJEktW,PbCwLCx,WMkiGJZp){" fullword ascii
    $s5  = "function ZowaJw(oKMyAL){return oKMyAL.ExpandEnvironmentStrings(JzepKioCJokAFrczM[10])}" fullword ascii
    $s6  = "function gCTMh(cVVQiZJR,lGhvfM,UqgRaLgSg){KcLLr=cVVQiZJR.split(UqgRaLgSg);xjIeDVc = JzepKioCJokAFrczM[13];for(syopwaeg=0;syopwae" ascii
    $s7  = "function vNTzG(SogNdeJi,UvtJn,RWIIyCWdTY){SogNdeJi.open();SogNdeJi.type = 1;SogNdeJi.write(UvtJn);SogNdeJi.position = 0;SogNdeJi" ascii
    $s8  = "function gCTMh(cVVQiZJR,lGhvfM,UqgRaLgSg){KcLLr=cVVQiZJR.split(UqgRaLgSg);xjIeDVc = JzepKioCJokAFrczM[13];for(syopwaeg=0;syopwae" ascii
    $s9  = "or(Math.random()*XQwWxdPX.length));}return womKY;}" fullword ascii
    $s10 = "function TWhv(omVDBx,mJyBMyv){Xyil = JzepKioCJokAFrczM[11].split(JzepKioCJokAFrczM[12]);mJyBMyv.open(Xyil[0]+Xyil[2]+Xyil[3], om" ascii
    $s11 = "function vNTzG(SogNdeJi,UvtJn,RWIIyCWdTY){SogNdeJi.open();SogNdeJi.type = 1;SogNdeJi.write(UvtJn);SogNdeJi.position = 0;SogNdeJi" ascii
    $s12 = "function TWhv(omVDBx,mJyBMyv){Xyil = JzepKioCJokAFrczM[11].split(JzepKioCJokAFrczM[12]);mJyBMyv.open(Xyil[0]+Xyil[2]+Xyil[3], om" ascii
    $s13 = "VDBx, false);mJyBMyv.send();}" fullword ascii
    $s14 = "function wwzRN(oKMyAL){return new ActiveXObject(oKMyAL);}" fullword ascii
    $s15 = "g<lGhvfM.length;syopwaeg++) {xjIeDVc+=KcLLr[lGhvfM[syopwaeg]];}return xjIeDVc.substring(3,xjIeDVc.length);}" fullword ascii
    $s16 = "function UcJPFRO() {var uWtg=100000;var jzvcGt = 100;return Math.random()*(uWtg-jzvcGt)+jzvcGt;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}