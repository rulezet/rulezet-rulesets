rule sig_20151216_d4ed0c536d8cf5a9891510fd080b4097 {
  meta:
    description = "datamaliciousorder - file 20151216_d4ed0c536d8cf5a9891510fd080b4097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbff90f855b26509ffb1ffac09505cc57283dbddb8dc7cee0ab2aa3d2b46dc70"

  strings:
    $s1  = "function NrKDIWP(ACnqBhDXmXGdkmspYETPTvjdncXgCzJioomM) {return !GVDMoUQisPo(whnEJbTKSsmzeXL(ACnqBhDXmXGdkmspYETPTvjdncXgCzJioomM" ascii
    $s2  = ") - 1));while(true){if (piIzdXKWyNo >= (3195+855)/675){break;}nNhhsrwvd[piIzdXKWyNo]=Math.round((Math.pow(Math.sin(776), 2) + Ma" ascii
    $s3  = "function qBBDBpGVOiTclqupo(verHE){lneWiELVbwM= '';piIzdXKWyNo=Math.round((Math.pow(Math.sin(897), 2) + Math.pow(Math.cos(897), 2" ascii
    $s4  = "w(Math.cos(652), 2) - 1)));} nNhhsrwvd[piIzdXKWyNo]++;}piIzdXKWyNo++;} return lneWiELVbwM}" fullword ascii
    $s5  = "th.pow(Math.cos(776), 2) - 1)); while(true) { if(nNhhsrwvd[piIzdXKWyNo] > verHE[piIzdXKWyNo].length-(5+353)/358) { break; } if (" ascii
    $s6  = "function qBBDBpGVOiTclqupo(verHE){lneWiELVbwM= '';piIzdXKWyNo=Math.round((Math.pow(Math.sin(897), 2) + Math.pow(Math.cos(897), 2" ascii
    $s7  = "function FSUQiRCtBcoK(OkbfRYBkxYJum) {return isFinite(OkbfRYBkxYJum);}" fullword ascii
    $s8  = "function NrKDIWP(ACnqBhDXmXGdkmspYETPTvjdncXgCzJioomM) {return !GVDMoUQisPo(whnEJbTKSsmzeXL(ACnqBhDXmXGdkmspYETPTvjdncXgCzJioomM" ascii
    $s9  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s10 = "function twkdkDoncVuJlpguSZjZTywNktmVKdKIvICfjUdJDmkiTASgumBEML(MgUALKinRFIyL,RMcDULCevGwdsh){ return RQcmybj[OlIUSgAL[SJvBr(MgU" ascii
    $s11 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s12 = "function h(YMuSYWdxrwDaso,vvuNqVfKDLTXW,DnXPjniiRkg) {YMuSYWdxrwDaso[vvuNqVfKDLTXW]=DnXPjniiRkg;}" fullword ascii
    $s13 = "function SJvBr(BfXdeKtgrAa,mqyYZnxAouShj,TACFAfcd){jXZt=WNruXMvwkzzovsCQf(BfXdeKtgrAa,mqyYZnxAouShj);pmiKr=jXZt.toString(TACFAfc" ascii
    $s14 = "function twkdkDoncVuJlpguSZjZTywNktmVKdKIvICfjUdJDmkiTASgumBEML(MgUALKinRFIyL,RMcDULCevGwdsh){ return RQcmybj[OlIUSgAL[SJvBr(MgU" ascii
    $s15 = "function whnEJbTKSsmzeXL(PjYHJAfJVQVorbuolmO) {return parseFloat(PjYHJAfJVQVorbuolmO);}" fullword ascii
    $s16 = "function SJvBr(BfXdeKtgrAa,mqyYZnxAouShj,TACFAfcd){jXZt=WNruXMvwkzzovsCQf(BfXdeKtgrAa,mqyYZnxAouShj);pmiKr=jXZt.toString(TACFAfc" ascii
    $s17 = "d);return pmiKr;}" fullword ascii
    $s18 = "function x(yzUleRUvDEyM,jsRaeBEQNjqthT){yzUleRUvDEyM.push(jsRaeBEQNjqthT);}" fullword ascii
    $s19 = "function JqcRrnONxLoXlFd(EloRsbvLHAwwJAJCH,lfkDeePCVJuHpitRDJycMJoVMywWahrusT,gtOSLqblHusglJeFjLaFIkjEVGPmufpYBgV){eval(EloRsbvL" ascii
    $s20 = "function GVDMoUQisPo(IUDGlsSrzgTzPY) {return isNaN(IUDGlsSrzgTzPY);}" fullword ascii

  condition:
    uint16(0) == 0x6c4f and
    8 of them
}