rule sig_20151216_c436f3525a78b973fbd64f3fbab98542 {
  meta:
    description = "datamaliciousorder - file 20151216_c436f3525a78b973fbd64f3fbab98542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c20c2784e79ecc808fba3fa8086dec16b66124aa2bea90b758b5fdd2d811231"

  strings:
    $s1  = ".pow(Math.cos(901), 2) - 1)); while(true) { if(DcxASOssW[XkXXLaFvJMm] > MyAuq[XkXXLaFvJMm].length-(-12+858)/846) { break; } if (" ascii
    $s2  = "w(Math.cos(966), 2) - 1)));} DcxASOssW[XkXXLaFvJMm]++;}XkXXLaFvJMm++;} return wOaHmbuIdXW}" fullword ascii
    $s3  = "- 1));while(true){if (XkXXLaFvJMm >= (1956+990)/491){break;}DcxASOssW[XkXXLaFvJMm]=Math.round((Math.pow(Math.sin(901), 2) + Math" ascii
    $s4  = "function OPcaCPswFJmPLEegN(MyAuq){wOaHmbuIdXW= '';XkXXLaFvJMm=Math.round((Math.pow(Math.sin(75), 2) + Math.pow(Math.cos(75), 2) " ascii
    $s5  = "function OPcaCPswFJmPLEegN(MyAuq){wOaHmbuIdXW= '';XkXXLaFvJMm=Math.round((Math.pow(Math.sin(75), 2) + Math.pow(Math.cos(75), 2) " ascii
    $s6  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s7  = "function GydMfDACotIh(ydJnSEaVOiDIc) {return isFinite(ydJnSEaVOiDIc);}" fullword ascii
    $s8  = "function BoELUHJSNLt(NcizXVFhlTYMWu) {return isNaN(NcizXVFhlTYMWu);}" fullword ascii
    $s9  = "function icWUiheYhbxpWClUMdEQWVTkNBJZRNPFJFGJmScsxMbwaTGpylwjok(aOoDKgjQYgkYT,ynkSEVOZdoZgnL){ return pnGpHBr[DONqNAXn[XSzAS(aOo" ascii
    $s10 = "function O(sXcuOGFPnXHlGD,aOfXWqeEiywAg,BztElrIIpqn) {sXcuOGFPnXHlGD[aOfXWqeEiywAg]=BztElrIIpqn;}" fullword ascii
    $s11 = "function npGKgMlFsqzxNap(ehMWuVXIaFsjEEovsYG) {return parseFloat(ehMWuVXIaFsjEEovsYG);}" fullword ascii
    $s12 = "function KvMcVScNebdWEpC(ulTuAnfEKcMhXObmA,hzPchiqskKwgRLzVzNmJzfjiweyQrOIYRk,YmTysArDcKETvFpOuAxNxnGYOffwrpYCpIh){eval(ulTuAnfE" ascii
    $s13 = "function A(kwkoFxsgDZLQ,EKzihVBHCJXdRn){kwkoFxsgDZLQ.push(EKzihVBHCJXdRn);}" fullword ascii
    $s14 = "function XSzAS(TsYOaASIwBW,TUHemNcLqfYSJ,FOnWyReQ){FTDM=KlDlMzyUWEGZeqvaz(TsYOaASIwBW,TUHemNcLqfYSJ);FsbLI=FTDM.toString(FOnWyRe" ascii
    $s15 = "function XSzAS(TsYOaASIwBW,TUHemNcLqfYSJ,FOnWyReQ){FTDM=KlDlMzyUWEGZeqvaz(TsYOaASIwBW,TUHemNcLqfYSJ);FsbLI=FTDM.toString(FOnWyRe" ascii
    $s16 = "function icWUiheYhbxpWClUMdEQWVTkNBJZRNPFJFGJmScsxMbwaTGpylwjok(aOoDKgjQYgkYT,ynkSEVOZdoZgnL){ return pnGpHBr[DONqNAXn[XSzAS(aOo" ascii
    $s17 = "Q);return FsbLI;}" fullword ascii
    $s18 = "function KlDlMzyUWEGZeqvaz(ZkmtGUfDKc,dQYxyzBsUK) {return parseInt(ZkmtGUfDKc,dQYxyzBsUK);}" fullword ascii
    $s19 = "function KvMcVScNebdWEpC(ulTuAnfEKcMhXObmA,hzPchiqskKwgRLzVzNmJzfjiweyQrOIYRk,YmTysArDcKETvFpOuAxNxnGYOffwrpYCpIh){eval(ulTuAnfE" ascii
    $s20 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4f44 and
    8 of them
}