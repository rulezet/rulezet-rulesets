rule sig_20151209_14ee8d4715764ba4baa4ca5d5f09e4e0 {
  meta:
    description = "datamaliciousorder - file 20151209_14ee8d4715764ba4baa4ca5d5f09e4e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "704d9108536fba28c12d21727a0ce12c22fc0a83eacfe391d49ea6f36512989c"

  strings:
    $s1  = "function rojCZYO(AxKDThdlVjwDVsHzdeuPbdtLBsAvhmcWIrRO) {return !isNaN(parseFloat(AxKDThdlVjwDVsHzdeuPbdtLBsAvhmcWIrRO)) && isFin" ascii
    $s2  = "function rojCZYO(AxKDThdlVjwDVsHzdeuPbdtLBsAvhmcWIrRO) {return !isNaN(parseFloat(AxKDThdlVjwDVsHzdeuPbdtLBsAvhmcWIrRO)) && isFin" ascii
    $s3  = "function hpgreWtbGzBbVrpoF(rGRFj){SsvFaglSCeS= '';for(BxnusGGiKOY=(-484+484)/455; BxnusGGiKOY < (1118+478)/798; BxnusGGiKOY++) {" ascii
    $s4  = "++;}} return SsvFaglSCeS}" fullword ascii
    $s5  = "jBkusWuui[BxnusGGiKOY]=(-625+625)/706; while(true) { if(jBkusWuui[BxnusGGiKOY] > rGRFj[BxnusGGiKOY].length-(300+391)/691) { brea" ascii
    $s6  = "function PHBrW(VYjmwauORRd,qqBEmVVLmVFaw,puvOSeqI){yTRk=parseInt(VYjmwauORRd,qqBEmVVLmVFaw);lvxuG=yTRk.toString(puvOSeqI);return" ascii
    $s7  = "function hpgreWtbGzBbVrpoF(rGRFj){SsvFaglSCeS= '';for(BxnusGGiKOY=(-484+484)/455; BxnusGGiKOY < (1118+478)/798; BxnusGGiKOY++) {" ascii
    $s8  = "function mOSFjuOSlajwrUmmcSBxiHxUWKTOTBzKRClPajkPeltDUpiBUYFIVb(rnnhTpSUczftn,gKjEKGNkqCJmuq){ return NFGlg[PHBrW(rnnhTpSUczftn[" ascii
    $s9  = "function DsBJuMwaEkf(RLsTgyOl,nRqoHh){return RLsTgyOl.split(nRqoHh)}" fullword ascii
    $s10 = "function mOSFjuOSlajwrUmmcSBxiHxUWKTOTBzKRClPajkPeltDUpiBUYFIVb(rnnhTpSUczftn,gKjEKGNkqCJmuq){ return NFGlg[PHBrW(rnnhTpSUczftn[" ascii
    $s11 = "function PHBrW(VYjmwauORRd,qqBEmVVLmVFaw,puvOSeqI){yTRk=parseInt(VYjmwauORRd,qqBEmVVLmVFaw);lvxuG=yTRk.toString(puvOSeqI);return" ascii
    $s12 = " lvxuG;}function czTnMndrMHteMfC(WGFhJQQBqsLqtehUL){eval(WGFhJQQBqsLqtehUL)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}