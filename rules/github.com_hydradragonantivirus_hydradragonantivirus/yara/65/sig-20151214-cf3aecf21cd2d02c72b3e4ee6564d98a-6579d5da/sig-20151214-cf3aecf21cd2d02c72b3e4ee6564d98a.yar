rule sig_20151214_cf3aecf21cd2d02c72b3e4ee6564d98a {
  meta:
    description = "datamaliciousorder - file 20151214_cf3aecf21cd2d02c72b3e4ee6564d98a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "558f603559005e65408c35e0b563ef2b7249324fe1100740fd34429b62a69cd4"

  strings:
    $s1  = "th.cos(846), 2) - 1)));} WXmlqKbiU[vqBHgibmDPa]++;}} return fzEipvwdSjB}" fullword ascii
    $s2  = "function kRqtOzzMkHnDXbTho(byuDa){fzEipvwdSjB= a[1760];for(vqBHgibmDPa=Math.round((Math.pow(Math.sin(92), 2) + Math.pow(Math.cos" ascii
    $s3  = "h.pow(Math.cos(795), 2) - 1)); while(true) { if(WXmlqKbiU[vqBHgibmDPa] > byuDa[vqBHgibmDPa].length-(75+716)/791) { break; } if (" ascii
    $s4  = "function kRqtOzzMkHnDXbTho(byuDa){fzEipvwdSjB= a[1760];for(vqBHgibmDPa=Math.round((Math.pow(Math.sin(92), 2) + Math.pow(Math.cos" ascii
    $s5  = "function ewartPN(FjGrXcvvJFYzzJfFdNFYOnpizyHLUTLdZNBD) {return !isNaN(parseFloat(FjGrXcvvJFYzzJfFdNFYOnpizyHLUTLdZNBD)) && isFin" ascii
    $s6  = "function ewartPN(FjGrXcvvJFYzzJfFdNFYOnpizyHLUTLdZNBD) {return !isNaN(parseFloat(FjGrXcvvJFYzzJfFdNFYOnpizyHLUTLdZNBD)) && isFin" ascii
    $s7  = "var a=new Array();" fullword ascii
    $s8  = "function zDgZiOLWYQd(THPnybqe,KaTAxy){return THPnybqe.split(KaTAxy)}" fullword ascii
    $s9  = "function IOTPlLkhroJyLMBTLUqLLaReBToWrsIhvGGKjQJQjSIDeyKeJaFtNQ(qaRIdVwuygeYG,LcoVVJDMWymvfL){ return NUVfgrh[gvAmPmIP[wIxsz(qaR" ascii
    $s10 = "function wIxsz(YatPEalOtKw,LjsYXzJtNmncN,hbTDWXET){lQJY=parseInt(YatPEalOtKw,LjsYXzJtNmncN);bqANX=lQJY.toString(hbTDWXET);return" ascii
    $s11 = "function h(mUnUJWFnMpfu,msWNNmTEBCEDlM){mUnUJWFnMpfu.push(msWNNmTEBCEDlM);}function a8(camtQaGNOevmlXMg){if(ewartPN(camtQaGNOevm" ascii
    $s12 = "function wIxsz(YatPEalOtKw,LjsYXzJtNmncN,hbTDWXET){lQJY=parseInt(YatPEalOtKw,LjsYXzJtNmncN);bqANX=lQJY.toString(hbTDWXET);return" ascii
    $s13 = " bqANX;}function dikNxPQDULtsXKN(FuzYvrmUDvJVMRfLN,pKvADBwaGFlHJyHexoGjwuikydrvoPVTYh,DjfeACEhslBVPlMFgcGFHhtnVUTcnTrTqyC){eval(" ascii
    $s14 = "function IOTPlLkhroJyLMBTLUqLLaReBToWrsIhvGGKjQJQjSIDeyKeJaFtNQ(qaRIdVwuygeYG,LcoVVJDMWymvfL){ return NUVfgrh[gvAmPmIP[wIxsz(qaR" ascii
    $s15 = "function dikNxPQDULtsXKN(FuzYvrmUDvJVMRfLN){eval(FuzYvrmUDvJVMRfLN)}" fullword ascii
    $s16 = "lXMg)) {return (String.fromCharCode(camtQaGNOevmlXMg) + String.fromCharCode((3039+743)/62));}}" fullword ascii
    $s17 = "function h(mUnUJWFnMpfu,msWNNmTEBCEDlM){mUnUJWFnMpfu.push(msWNNmTEBCEDlM);}function a8(camtQaGNOevmlXMg){if(ewartPN(camtQaGNOevm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}