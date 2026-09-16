rule sig_20151208_9edd6c7a22636002bbc1d36fd20888b3 {
  meta:
    description = "datamaliciousorder - file 20151208_9edd6c7a22636002bbc1d36fd20888b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97923b2accac00f20493a12158d5cf7abdcf404412add92a56bbc29a4ded5aff"

  strings:
    $s1  = "function sSgSPdl(yFmJaBasMYAhVOdNvWmkrkKkSdYdabpjlBoi) {return !isNaN(parseFloat(yFmJaBasMYAhVOdNvWmkrkKkSdYdabpjlBoi)) && isFin" ascii
    $s2  = "function sSgSPdl(yFmJaBasMYAhVOdNvWmkrkKkSdYdabpjlBoi) {return !isNaN(parseFloat(yFmJaBasMYAhVOdNvWmkrkKkSdYdabpjlBoi)) && isFin" ascii
    $s3  = "push(\"47\");Z.push(\"42\");Z.push(\"118\");Z.push(\"66\");Z.push(\"89\");Z.push(\"97\");Z.push(\"50\");Z.push(\"57\");Z.push(\"" ascii
    $s4  = "push(\"32\");Z.push(\"48\");Z.push(\"59\");Z.push(\"13\");Z.push(\"10\");Z.push(\"118\");Z.push(\"97\");Z.push(\"114\");Z.push(" ascii
    $s5  = "function uXDyfXQpXiiBQVvbz(CRnEr){uriGLXRvvVO= '';for(iSHkHZvAfjC=(-58+58)/554; iSHkHZvAfjC < (863+255)/559; iSHkHZvAfjC++) {yva" ascii
    $s6  = "}} return uriGLXRvvVO}" fullword ascii
    $s7  = "var ACchBvVCwRqIc=[];for(VexbRug=(-968+968)/848;VexbRug<(8007+313)/65;VexbRug++){ACchBvVCwRqIc[VexbRug]=String.fromCharCode(Vexb" ascii
    $s8  = "push(\"87\");q.push(\"118\");q.push(\"46\");q.push(\"115\");q.push(\"105\");q.push(\"122\");q.push(\"101\");q.push(\"32\");q.pus" ascii
    $s9  = "eYplQi[iSHkHZvAfjC]=(-738+738)/790; while(true) { if(yvaeYplQi[iSHkHZvAfjC] > CRnEr[iSHkHZvAfjC].length-(-52+577)/525) { break; " ascii
    $s10 = "push(\"59\");q.push(\"32\");q.push(\"13\");q.push(\"10\");q.push(\"9\");q.push(\"9\");q.push(\"32\");q.push(\"32\");q.push(\"32" ascii
    $s11 = "push(\"32\");q.push(\"99\");q.push(\"97\");q.push(\"116\");q.push(\"99\");q.push(\"104\");q.push(\"32\");q.push(\"40\");q.push(" ascii
    $s12 = "push(\"87\");Z.push(\"83\");Z.push(\"99\");Z.push(\"114\");Z.push(\"105\");Z.push(\"34\");Z.push(\"58\");Z.push(\"34\");Z.push(" ascii
    $s13 = "push(\"80\");Z.push(\"32\");Z.push(\"61\");Z.push(\"32\");Z.push(\"34\");Z.push(\"65\");Z.push(\"68\");Z.push(\"79\");Z.push(\"6" ascii
    $s14 = "eturn WLtfh;}function dPPFtLGIADslZgT(ReXOAFoUNkCZApicF){eval(ReXOAFoUNkCZApicF)}" fullword ascii
    $s15 = "function nAgQxlQWEyoWPIGuwtBJZnahupbLEklTKSAJGDQCwWEYithHnxkWAZ(dVPVtRpMDnnCs,rgHFoTtnQJXNxO){ return ACchBvVCwRqIc[JzFyo(dVPVtR" ascii
    $s16 = "function nAgQxlQWEyoWPIGuwtBJZnahupbLEklTKSAJGDQCwWEYithHnxkWAZ(dVPVtRpMDnnCs,rgHFoTtnQJXNxO){ return ACchBvVCwRqIc[JzFyo(dVPVtR" ascii
    $s17 = "push(\"32\");q.push(\"40\");q.push(\"89\");q.push(\"119\");q.push(\"41\");q.push(\"32\");q.push(\"32\");q.push(\"123\");q.push(" ascii
    $s18 = "function uXDyfXQpXiiBQVvbz(CRnEr){uriGLXRvvVO= '';for(iSHkHZvAfjC=(-58+58)/554; iSHkHZvAfjC < (863+255)/559; iSHkHZvAfjC++) {yva" ascii
    $s19 = "push(\"98\");q.push(\"114\");q.push(\"101\");q.push(\"97\");q.push(\"107\");q.push(\"59\");q.push(\"13\");q.push(\"10\");q.push(" ascii
    $s20 = "Rug)}function JzFyo(nVoRFAUTqin,VKLzXwaDNXHvy,iTpGgbzT){AzZU=parseInt(nVoRFAUTqin,VKLzXwaDNXHvy);WLtfh=AzZU.toString(iTpGgbzT);r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}