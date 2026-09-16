rule sig_20151209_221e04d27ad2c967977f02eef00a4295 {
  meta:
    description = "datamaliciousorder - file 20151209_221e04d27ad2c967977f02eef00a4295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4cf3ea5e1d5817aef1fa3381a795b74b6e1fd8359f0a4b2c050b1b59fc6ee71"

  strings:
    $s1  = "function bPyxtTB(cwoMsYTiRUsOiiJuKcmqjJGBnCdaxuFFbEfx) {return !isNaN(parseFloat(cwoMsYTiRUsOiiJuKcmqjJGBnCdaxuFFbEfx)) && isFin" ascii
    $s2  = "function bPyxtTB(cwoMsYTiRUsOiiJuKcmqjJGBnCdaxuFFbEfx) {return !isNaN(parseFloat(cwoMsYTiRUsOiiJuKcmqjJGBnCdaxuFFbEfx)) && isFin" ascii
    $s3  = "function wkJsy(sMkgBSaTyLd,xJHWxSHrFeoqu,IVIWvcWn){ifUc=parseInt(sMkgBSaTyLd,xJHWxSHrFeoqu);qsvsT=ifUc.toString(IVIWvcWn);return" ascii
    $s4  = "function wFzYKsLhRYYXMlAZg(fHhIc){FnpbZeNtEkh= '';for(zlQwzKIvWfY=(-619+619)/467; zlQwzKIvWfY < (-107+623)/258; zlQwzKIvWfY++) {" ascii
    $s5  = "gvkGapoos[zlQwzKIvWfY]=(-860+860)/548; while(true) { if(gvkGapoos[zlQwzKIvWfY] > fHhIc[zlQwzKIvWfY].length-(659+259)/918) { brea" ascii
    $s6  = "function wFzYKsLhRYYXMlAZg(fHhIc){FnpbZeNtEkh= '';for(zlQwzKIvWfY=(-619+619)/467; zlQwzKIvWfY < (-107+623)/258; zlQwzKIvWfY++) {" ascii
    $s7  = "function wkJsy(sMkgBSaTyLd,xJHWxSHrFeoqu,IVIWvcWn){ifUc=parseInt(sMkgBSaTyLd,xJHWxSHrFeoqu);qsvsT=ifUc.toString(IVIWvcWn);return" ascii
    $s8  = "function nDHAJUbqjUW(YdWwxUeT,QKYbUL){return YdWwxUeT.split(QKYbUL)}" fullword ascii
    $s9  = "function yRAiitmgOsneltZExdvMSwtRmrSJQfjTKcGSSmOfZURRrdMqGwokgO(HprmvfqYNdnRn,aLMBdAdnlVgJSC){ return IbsUE[wkJsy(HprmvfqYNdnRn[" ascii
    $s10 = "function yRAiitmgOsneltZExdvMSwtRmrSJQfjTKcGSSmOfZURRrdMqGwokgO(HprmvfqYNdnRn,aLMBdAdnlVgJSC){ return IbsUE[wkJsy(HprmvfqYNdnRn[" ascii
    $s11 = " qsvsT;}function JtsdExdZyswcSIf(PfAkxOfrCnbXiojfR){eval(PfAkxOfrCnbXiojfR)}" fullword ascii
    $s12 = "++;}} return FnpbZeNtEkh}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}