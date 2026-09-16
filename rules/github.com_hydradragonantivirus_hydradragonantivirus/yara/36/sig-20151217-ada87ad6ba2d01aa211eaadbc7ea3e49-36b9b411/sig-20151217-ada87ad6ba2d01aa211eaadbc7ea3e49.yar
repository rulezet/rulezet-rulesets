rule sig_20151217_ada87ad6ba2d01aa211eaadbc7ea3e49 {
  meta:
    description = "datamaliciousorder - file 20151217_ada87ad6ba2d01aa211eaadbc7ea3e49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5eb037026adf2b9a349291fba2e8e9675941c3f3c80a14966a05858ec5ba174b"

  strings:
    $s1  = ") - 1));while(true){if (PjCfqOqNBGT >= (660+690)/225){break;}BoQVyYZiA[PjCfqOqNBGT]=Math.round((Math.pow(Math.sin(854), 2) + Mat" ascii
    $s2  = "function zFdXPbvnAiWfAaEZb(czUCI){uReIyFqXhjH= '';PjCfqOqNBGT=Math.round((Math.pow(Math.sin(287), 2) + Math.pow(Math.cos(287), 2" ascii
    $s3  = "(Math.cos(397), 2) - 1)));} BoQVyYZiA[PjCfqOqNBGT]++;}PjCfqOqNBGT++;} return uReIyFqXhjH}" fullword ascii
    $s4  = "h.pow(Math.cos(854), 2) - 1)); while(true) { if(BoQVyYZiA[PjCfqOqNBGT] > czUCI[PjCfqOqNBGT].length-(55+342)/397) { break; } if (" ascii
    $s5  = "function zFdXPbvnAiWfAaEZb(czUCI){uReIyFqXhjH= '';PjCfqOqNBGT=Math.round((Math.pow(Math.sin(287), 2) + Math.pow(Math.cos(287), 2" ascii
    $s6  = "function acdASxJeGlrvYbF(IBuoUyyHzESVgVOqz,bavXRabxqVgNKtWJfXxeezXMlqxlMOOXyG,UBoGADuNilKqREAvpDKEYTMuBqSiQIhNltU){eval(IBuoUyyH" ascii
    $s7  = "function OLgaGRR(rZrbEHcyDMYgMKQsEsNaiRDnyDghjqmpOlIW) {return !ChbscOzUrjN(mvNkNNvHiGuIrDd(rZrbEHcyDMYgMKQsEsNaiRDnyDghjqmpOlIW" ascii
    $s8  = "function acdASxJeGlrvYbF(IBuoUyyHzESVgVOqz,bavXRabxqVgNKtWJfXxeezXMlqxlMOOXyG,UBoGADuNilKqREAvpDKEYTMuBqSiQIhNltU){eval(IBuoUyyH" ascii
    $s9  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s10 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s11 = "function mGiHnHJJMPSBBzxSKThINgTmMijyFbCClWRhmkwWrgovBpptfGgjEy(LKdoGJYdRwCGu,eAfsPZAvyhkpWI){ return TlnVWHv[pJBwOqtA[vjnBT(LKd" ascii
    $s12 = "i);return DWmKE;}" fullword ascii
    $s13 = "function vjnBT(xgAYrzFLCcU,kYeDdBDvRlebW,sMtyuzzi){uIiC=ycMlqbXJAdHAvYdZE(xgAYrzFLCcU,kYeDdBDvRlebW);DWmKE=uIiC.toString(sMtyuzz" ascii
    $s14 = "function xHpkPRiBBYPY(sPbVeANhmVqYx) {return isFinite(sPbVeANhmVqYx);}" fullword ascii
    $s15 = "function ycMlqbXJAdHAvYdZE(ESZHmIxUsu,YPNyraTQyS) {return parseInt(ESZHmIxUsu,YPNyraTQyS);}" fullword ascii
    $s16 = "function vjnBT(xgAYrzFLCcU,kYeDdBDvRlebW,sMtyuzzi){uIiC=ycMlqbXJAdHAvYdZE(xgAYrzFLCcU,kYeDdBDvRlebW);DWmKE=uIiC.toString(sMtyuzz" ascii
    $s17 = "function mvNkNNvHiGuIrDd(TKkHSBIFDytuCgiTwEQ) {return parseFloat(TKkHSBIFDytuCgiTwEQ);}" fullword ascii
    $s18 = "function n(UdYAcFqZVlrUcg,hphMIajeJBgqX,NvrnGuxovlH) {UdYAcFqZVlrUcg[hphMIajeJBgqX]=NvrnGuxovlH;}" fullword ascii
    $s19 = "function OLgaGRR(rZrbEHcyDMYgMKQsEsNaiRDnyDghjqmpOlIW) {return !ChbscOzUrjN(mvNkNNvHiGuIrDd(rZrbEHcyDMYgMKQsEsNaiRDnyDghjqmpOlIW" ascii
    $s20 = "function F(jSiUKyadQAdl,WawQyktTrZHwNZ){jSiUKyadQAdl.push(WawQyktTrZHwNZ);}" fullword ascii

  condition:
    uint16(0) == 0x4a70 and
    8 of them
}