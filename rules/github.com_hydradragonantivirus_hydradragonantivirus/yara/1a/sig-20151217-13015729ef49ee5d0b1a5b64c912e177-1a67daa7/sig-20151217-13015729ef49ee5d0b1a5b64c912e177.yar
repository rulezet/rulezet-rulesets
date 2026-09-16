rule sig_20151217_13015729ef49ee5d0b1a5b64c912e177 {
  meta:
    description = "datamaliciousorder - file 20151217_13015729ef49ee5d0b1a5b64c912e177.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85bc5f9f3a61ae5d48cbe85c4dad438ec7c001451e70f9f0d28d33564148319b"

  strings:
    $s1  = "function mAMoqIcHjgSDqhgVR(wZNCp){TYAFeVukswv= '';WlbmssgBlCQ=Math.round((Math.pow(Math.sin(896), 2) + Math.pow(Math.cos(896), 2" ascii
    $s2  = ") - 1));while(true){if (WlbmssgBlCQ >= (961+203)/194){break;}mYIAPqZKt[WlbmssgBlCQ]=Math.round((Math.pow(Math.sin(809), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(809), 2) - 1)); while(true) { if(mYIAPqZKt[WlbmssgBlCQ] > wZNCp[WlbmssgBlCQ].length-(-181+940)/759) { break; } if" ascii
    $s4  = "ow(Math.cos(132), 2) - 1)));} mYIAPqZKt[WlbmssgBlCQ]++;}WlbmssgBlCQ++;} return TYAFeVukswv}" fullword ascii
    $s5  = "function mAMoqIcHjgSDqhgVR(wZNCp){TYAFeVukswv= '';WlbmssgBlCQ=Math.round((Math.pow(Math.sin(896), 2) + Math.pow(Math.cos(896), 2" ascii
    $s6  = "function BSTxBUX(KCQMCmVytNJJFxCGaHiwumENJdtgTSLeITpm) {return !ifAHrNaPSey(SkypCJiTdBdEVsh(KCQMCmVytNJJFxCGaHiwumENJdtgTSLeITpm" ascii
    $s7  = "S);return klVDD;}" fullword ascii
    $s8  = "function PBWkyLiOKfYqYqQ(FRqlgjgzUWAbPRAJw,bvimsDZQGcEqxOMfpNMcnCrJUAwKRxkpSL,PSeVpRyXddAAQVTaTFqnmIVxoZdhPhDpyIZ){eval(FRqlgjgz" ascii
    $s9  = "function PBWkyLiOKfYqYqQ(FRqlgjgzUWAbPRAJw,bvimsDZQGcEqxOMfpNMcnCrJUAwKRxkpSL,PSeVpRyXddAAQVTaTFqnmIVxoZdhPhDpyIZ){eval(FRqlgjgz" ascii
    $s10 = "function aYgXjNtnqHcLzCjtbPsehpZRmnCPlxGEhMmdvAahrpfFGACdEnyGwT(FVQUPepLIZQLq,qyQmqbsyFJhJkz){ return pBcFJjl[oDyUvBSV[KcPTW(FVQ" ascii
    $s11 = "function KcPTW(pHtzfGkcmCy,PWxFOuJqkLUeg,SCRYeJBS){oNUk=tSEvyICkbTlfqRbSG(pHtzfGkcmCy,PWxFOuJqkLUeg);klVDD=oNUk.toString(SCRYeJB" ascii
    $s12 = "function MFqlHzumKbLP(cchkFvdPQNFDC) {return isFinite(cchkFvdPQNFDC);}" fullword ascii
    $s13 = "function BSTxBUX(KCQMCmVytNJJFxCGaHiwumENJdtgTSLeITpm) {return !ifAHrNaPSey(SkypCJiTdBdEVsh(KCQMCmVytNJJFxCGaHiwumENJdtgTSLeITpm" ascii
    $s14 = "function ifAHrNaPSey(pCiJfGlKrcsLJO) {return isNaN(pCiJfGlKrcsLJO);}" fullword ascii
    $s15 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s16 = "function C(fxzxotKMzqSjlh,vVHEXFFcxzZRU,YFuVmByHNIh) {fxzxotKMzqSjlh[vVHEXFFcxzZRU]=YFuVmByHNIh;}" fullword ascii
    $s17 = "function KcPTW(pHtzfGkcmCy,PWxFOuJqkLUeg,SCRYeJBS){oNUk=tSEvyICkbTlfqRbSG(pHtzfGkcmCy,PWxFOuJqkLUeg);klVDD=oNUk.toString(SCRYeJB" ascii
    $s18 = "function aYgXjNtnqHcLzCjtbPsehpZRmnCPlxGEhMmdvAahrpfFGACdEnyGwT(FVQUPepLIZQLq,qyQmqbsyFJhJkz){ return pBcFJjl[oDyUvBSV[KcPTW(FVQ" ascii
    $s19 = "function SkypCJiTdBdEVsh(NrcbgrZMIMMHISrhBoV) {return parseFloat(NrcbgrZMIMMHISrhBoV);}" fullword ascii
    $s20 = "function s(sqnoZZWVEYNY,DbZQFDhDsETtiy){sqnoZZWVEYNY.push(DbZQFDhDsETtiy);}" fullword ascii

  condition:
    uint16(0) == 0x446f and
    8 of them
}