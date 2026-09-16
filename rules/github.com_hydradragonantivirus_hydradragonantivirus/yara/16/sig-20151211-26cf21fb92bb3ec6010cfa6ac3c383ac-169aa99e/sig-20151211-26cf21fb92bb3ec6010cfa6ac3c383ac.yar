rule sig_20151211_26cf21fb92bb3ec6010cfa6ac3c383ac {
  meta:
    description = "datamaliciousorder - file 20151211_26cf21fb92bb3ec6010cfa6ac3c383ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a5b1da9a910919287cc032e9864256770d24f7f800cc14b52dd60e6aaf580b"

  strings:
    $s1  = "function cZEzbMu(wDziPHMRUqHmlYCDmVFUPQasdiNShaMvUySE) {return !isNaN(parseFloat(wDziPHMRUqHmlYCDmVFUPQasdiNShaMvUySE)) && isFin" ascii
    $s2  = "function cZEzbMu(wDziPHMRUqHmlYCDmVFUPQasdiNShaMvUySE) {return !isNaN(parseFloat(wDziPHMRUqHmlYCDmVFUPQasdiNShaMvUySE)) && isFin" ascii
    $s3  = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = " YBIFj;}function AjRylWHBKxPUOoh(rhyMTCphmYzZfVDJk){eval(rhyMTCphmYzZfVDJk)}" fullword ascii
    $s5  = "function AAfkYAvjlkZFdmXQF(PWBdm){NGMJRhXaleB= '';CcqAvKDJMRp=(-941+941)/261; while(true){if(CcqAvKDJMRp >= (-703+825)/61)break;" ascii
    $s6  = "]++;}CcqAvKDJMRp++;} return NGMJRhXaleB}" fullword ascii
    $s7  = "function gkTfr(CGCXcJDLBQU,vOysgKsvGjYAI,vVBBLHVe){soAG=parseInt(CGCXcJDLBQU,vOysgKsvGjYAI);YBIFj=soAG.toString(vVBBLHVe);return" ascii
    $s8  = "var P=new Array(\"2b\",\"2a\",\"28\",\"28\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s9  = "KBAnvSSCX[CcqAvKDJMRp]=(-169+169)/151; while(true) { if(KBAnvSSCX[CcqAvKDJMRp] > PWBdm[CcqAvKDJMRp].length-(417+197)/614) { brea" ascii
    $s10 = "var P=new Array(\"2b\",\"2a\",\"28\",\"28\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function thaLbuHFDyH(VofCPHwg,TGZgkE){return VofCPHwg.split(TGZgkE)}" fullword ascii
    $s13 = "function gkTfr(CGCXcJDLBQU,vOysgKsvGjYAI,vVBBLHVe){soAG=parseInt(CGCXcJDLBQU,vOysgKsvGjYAI);YBIFj=soAG.toString(vVBBLHVe);return" ascii
    $s14 = "function sXfjUODHXMKtPBAnsOHWIahwAbiJzEWScknPXmblOiAdyoITPJPcaF(DDlHfXvIHlarY,bGGRjQwrSdRKIR){ return YmzfR[gkTfr(DDlHfXvIHlarY[" ascii
    $s15 = "function AAfkYAvjlkZFdmXQF(PWBdm){NGMJRhXaleB= '';CcqAvKDJMRp=(-941+941)/261; while(true){if(CcqAvKDJMRp >= (-703+825)/61)break;" ascii
    $s16 = "function sXfjUODHXMKtPBAnsOHWIahwAbiJzEWScknPXmblOiAdyoITPJPcaF(DDlHfXvIHlarY,bGGRjQwrSdRKIR){ return YmzfR[gkTfr(DDlHfXvIHlarY[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}