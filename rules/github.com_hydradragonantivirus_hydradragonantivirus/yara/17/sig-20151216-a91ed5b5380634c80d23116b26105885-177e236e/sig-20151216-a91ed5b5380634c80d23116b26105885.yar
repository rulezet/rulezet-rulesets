rule sig_20151216_a91ed5b5380634c80d23116b26105885 {
  meta:
    description = "datamaliciousorder - file 20151216_a91ed5b5380634c80d23116b26105885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b67b4a98b6e8229f2c87f5bccc84ea79f624bbcac7203741d325977c6be97fcf"

  strings:
    $s1  = "ow(Math.cos(800), 2) - 1)));} SyzFHCwVw[GNJrfrJpfqP]++;}GNJrfrJpfqP++;} return kvAgNPXhciA}" fullword ascii
    $s2  = "th.pow(Math.cos(287), 2) - 1)); while(true) { if(SyzFHCwVw[GNJrfrJpfqP] > CewXl[GNJrfrJpfqP].length-(-490+879)/389) { break; } i" ascii
    $s3  = ") - 1));while(true){if (GNJrfrJpfqP >= (4594+434)/838){break;}SyzFHCwVw[GNJrfrJpfqP]=Math.round((Math.pow(Math.sin(287), 2) + Ma" ascii
    $s4  = "function nMnNsxNURMzwhBdjF(CewXl){kvAgNPXhciA= '';GNJrfrJpfqP=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s5  = "function nMnNsxNURMzwhBdjF(CewXl){kvAgNPXhciA= '';GNJrfrJpfqP=Math.round((Math.pow(Math.sin(760), 2) + Math.pow(Math.cos(760), 2" ascii
    $s6  = "function KVaIQmQ(wwiAngfYGEDAOeeyKrcDJncsDJXhGnnywvyP) {return !VRFuINYXvfm(fznbieERZLaWdlf(wwiAngfYGEDAOeeyKrcDJncsDJXhGnnywvyP" ascii
    $s7  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s8  = "function bpWUMAkECpZJPjB(MfCKksSBuPLcQWVXy,cNHCYXKyDdxTCSHdpwCOchsyMBVCrApIqj,TVGmtBJSBiZsINYCEEhVsrtyGQHQeRbJTqZ){eval(MfCKksSB" ascii
    $s9  = "function KVaIQmQ(wwiAngfYGEDAOeeyKrcDJncsDJXhGnnywvyP) {return !VRFuINYXvfm(fznbieERZLaWdlf(wwiAngfYGEDAOeeyKrcDJncsDJXhGnnywvyP" ascii
    $s10 = "function y(YGvgcVNIdzbG,bpoHuyutOcGxgF){YGvgcVNIdzbG.push(bpoHuyutOcGxgF);}" fullword ascii
    $s11 = "function q(WwgFmphvWsqBnA,wmoFQKpaFrHXQ,TPmvOaGRout) {WwgFmphvWsqBnA[wmoFQKpaFrHXQ]=TPmvOaGRout;}" fullword ascii
    $s12 = "function VRFuINYXvfm(bkYidptFRBcYNg) {return isNaN(bkYidptFRBcYNg);}" fullword ascii
    $s13 = "function OaXfKZNgSPVoPBeYZwuXNNrvkObEAfeZbfcbCwRXtNtgeLLsYugyCr(uMvDRxlBkWqxr,EthjCtHmvgIlqw){ return msIdlVJ[uNUZsWCh[pWEeZ(uMv" ascii
    $s14 = "function VfaQXPnsRRyVPzIPs(AnazxkyqQP,kaswFAWoMD) {return parseInt(AnazxkyqQP,kaswFAWoMD);}" fullword ascii
    $s15 = "function fznbieERZLaWdlf(rtJoguvJYHgQyzdDSXj) {return parseFloat(rtJoguvJYHgQyzdDSXj);}" fullword ascii
    $s16 = "function pWEeZ(uwCMWLsAaJg,VhvLzNITaztmm,tTDfiSmW){JZYn=VfaQXPnsRRyVPzIPs(uwCMWLsAaJg,VhvLzNITaztmm);CxpAU=JZYn.toString(tTDfiSm" ascii
    $s17 = "function ZoOlLkJleOTC(mAUenWmxuiTUj) {return isFinite(mAUenWmxuiTUj);}" fullword ascii
    $s18 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s19 = "W);return CxpAU;}" fullword ascii
    $s20 = "function bpWUMAkECpZJPjB(MfCKksSBuPLcQWVXy,cNHCYXKyDdxTCSHdpwCOchsyMBVCrApIqj,TVGmtBJSBiZsINYCEEhVsrtyGQHQeRbJTqZ){eval(MfCKksSB" ascii

  condition:
    uint16(0) == 0x4e75 and
    8 of them
}