rule sig_20151217_7281a7005e03e931e386b6faa987a48f {
  meta:
    description = "datamaliciousorder - file 20151217_7281a7005e03e931e386b6faa987a48f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da17adf5493390a15a991da903aba50bc82dd8f7220bbd50fcc728dd0d66183d"

  strings:
    $s1  = ") - 1));while(true){if (GeXFwarQDmw >= (4168+398)/761){break;}IxCxuMfQa[GeXFwarQDmw]=Math.round((Math.pow(Math.sin(313), 2) + Ma" ascii
    $s2  = "function LYCzwqesbrBWgsJTh(qWhFh){NNXErsMuhHy= '';GeXFwarQDmw=Math.round((Math.pow(Math.sin(574), 2) + Math.pow(Math.cos(574), 2" ascii
    $s3  = "ow(Math.cos(987), 2) - 1)));} IxCxuMfQa[GeXFwarQDmw]++;}GeXFwarQDmw++;} return NNXErsMuhHy}" fullword ascii
    $s4  = "th.pow(Math.cos(313), 2) - 1)); while(true) { if(IxCxuMfQa[GeXFwarQDmw] > qWhFh[GeXFwarQDmw].length-(30+742)/772) { break; } if " ascii
    $s5  = "function LYCzwqesbrBWgsJTh(qWhFh){NNXErsMuhHy= '';GeXFwarQDmw=Math.round((Math.pow(Math.sin(574), 2) + Math.pow(Math.cos(574), 2" ascii
    $s6  = "function TBqZZlo(DdbYRNKyiDixUqbINNonyMseqXytxgcFnrPB) {return !HZlFvyxcghB(uqqKAMFGfORuXOc(DdbYRNKyiDixUqbINNonyMseqXytxgcFnrPB" ascii
    $s7  = "function TBqZZlo(DdbYRNKyiDixUqbINNonyMseqXytxgcFnrPB) {return !HZlFvyxcghB(uqqKAMFGfORuXOc(DdbYRNKyiDixUqbINNonyMseqXytxgcFnrPB" ascii
    $s8  = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s9  = "function euqcj(LjBTegXrBBd,AKjkMWRBERqib,DJLlGXLI){mExq=phyqYLqMdvRGwKnpf(LjBTegXrBBd,AKjkMWRBERqib);jZkFx=mExq.toString(DJLlGXL" ascii
    $s10 = "function G(FqjdOLMTdAqQnZ,nzEAYiKGuimAX,dLEUsPPKEXr) {FqjdOLMTdAqQnZ[nzEAYiKGuimAX]=dLEUsPPKEXr;}" fullword ascii
    $s11 = "function X(EHSfUKAcSXQj,fuYgjqiRBCmWNt){EHSfUKAcSXQj.push(fuYgjqiRBCmWNt);}" fullword ascii
    $s12 = "function vSFuFbexxZOg(dHoSLcxhomaCF) {return isFinite(dHoSLcxhomaCF);}" fullword ascii
    $s13 = "function IfOCLnAKlUSVmwLSxACZWHcDguYijycznCDPCMKznsDiQWSFwMpJxi(KFqNbkqkVskTR,wdApaQsQLkCjxL){ return cOIXaQe[QFEEMpXC[euqcj(KFq" ascii
    $s14 = "I);return jZkFx;}" fullword ascii
    $s15 = "function phyqYLqMdvRGwKnpf(gSOrSJluFK,pTIiUKGhMq) {return parseInt(gSOrSJluFK,pTIiUKGhMq);}" fullword ascii
    $s16 = "function UjzADfxsTmHGDWu(zXeMqUKxASfwUjwlM,rJkicqCtiAwmfpSgmUgTbRvVVbDbFPdoET,LYvWnCJRAHXbjKpQVoTqTXMuzhaRUVXARqc){eval(zXeMqUKx" ascii
    $s17 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s18 = "function IfOCLnAKlUSVmwLSxACZWHcDguYijycznCDPCMKznsDiQWSFwMpJxi(KFqNbkqkVskTR,wdApaQsQLkCjxL){ return cOIXaQe[QFEEMpXC[euqcj(KFq" ascii
    $s19 = "function UjzADfxsTmHGDWu(zXeMqUKxASfwUjwlM,rJkicqCtiAwmfpSgmUgTbRvVVbDbFPdoET,LYvWnCJRAHXbjKpQVoTqTXMuzhaRUVXARqc){eval(zXeMqUKx" ascii
    $s20 = "function HZlFvyxcghB(niTwZfzbwBurGm) {return isNaN(niTwZfzbwBurGm);}" fullword ascii

  condition:
    uint16(0) == 0x4651 and
    8 of them
}