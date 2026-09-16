rule sig_20160520_649de153c92dfd30b842fe2bf1fae05c {
  meta:
    description = "datamaliciousorder - file 20160520_649de153c92dfd30b842fe2bf1fae05c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd744b466e0f75b2bb7ed40ce2248a8f676ab68d5699c8e99774c81e8f30878"

  strings:
    $s1  = "function IMZSqcof(bWWpo) {var BhpbuIwM=mVMycvDQDXP[2];for(var HJEuT=0;HJEuT<bWWpo;HJEuT++){XcxjI+=BhpbuIwM.charAt(Math.floor(Mat" ascii
    $s2  = "function IMZSqcof(bWWpo) {var BhpbuIwM=mVMycvDQDXP[2];for(var HJEuT=0;HJEuT<bWWpo;HJEuT++){XcxjI+=BhpbuIwM.charAt(Math.floor(Mat" ascii
    $s3  = "function ShSQulVkH(gAHIDAcIe,InSBXUY,mRbldoor){" fullword ascii
    $s4  = "function ZYoCD(emHXKzby,pfWYQL,dQMuIRcLv){Vtgue=emHXKzby.split(dQMuIRcLv);ScaicfU = mVMycvDQDXP[13];for(ukQDphnQ=0;ukQDphnQ<pfWY" ascii
    $s5  = "function ZYoCD(emHXKzby,pfWYQL,dQMuIRcLv){Vtgue=emHXKzby.split(dQMuIRcLv);ScaicfU = mVMycvDQDXP[13];for(ukQDphnQ=0;ukQDphnQ<pfWY" ascii
    $s6  = "function cJuAs(AEBmwHah,CNOcx,JkvmGglApT){AEBmwHah.open();AEBmwHah.type = 1;AEBmwHah.write(CNOcx);AEBmwHah.position = 0;AEBmwHah" ascii
    $s7  = "function cJuAs(AEBmwHah,CNOcx,JkvmGglApT){AEBmwHah.open();AEBmwHah.type = 1;AEBmwHah.write(CNOcx);AEBmwHah.position = 0;AEBmwHah" ascii
    $s8  = "function WrVp(AqkNwD,tdIIiFJ){KNjw = mVMycvDQDXP[11].split(mVMycvDQDXP[12]);tdIIiFJ.open(KNjw[0]+KNjw[2]+KNjw[3], AqkNwD, false)" ascii
    $s9  = "if (DwUwjYH==0) break;" fullword ascii
    $s10 = "function BNkCgSb() {var FYhe=100000;var gueysm = 100;return Math.random()*(FYhe-gueysm)+gueysm;}" fullword ascii
    $s11 = "function WrVp(AqkNwD,tdIIiFJ){KNjw = mVMycvDQDXP[11].split(mVMycvDQDXP[12]);tdIIiFJ.open(KNjw[0]+KNjw[2]+KNjw[3], AqkNwD, false)" ascii
    $s12 = "function sJEaO(yOHNAa){return new ActiveXObject(yOHNAa);}" fullword ascii
    $s13 = "function rHoton(yOHNAa){return yOHNAa.ExpandEnvironmentStrings(mVMycvDQDXP[10])}" fullword ascii
    $s14 = "try{DwUwjYH=ShSQulVkH(CqTZo[GiRJ], BNkCgSb() + mVMycvDQDXP[9], 1)}catch(e){}; " fullword ascii
    $s15 = "h.random()*BhpbuIwM.length));}return XcxjI;}" fullword ascii
    $s16 = "QL.length;ukQDphnQ++) {ScaicfU+=Vtgue[pfWYQL[ukQDphnQ]];}return ScaicfU.substring(3,ScaicfU.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}