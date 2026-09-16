rule sig_20151209_74f3bf91049ab9cdaf3c8bd492f1dde5 {
  meta:
    description = "datamaliciousorder - file 20151209_74f3bf91049ab9cdaf3c8bd492f1dde5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2ac951dd55f013bf9534bcafafd75ddc3afae08fb8fd34007f817a47523eec1"

  strings:
    $s1  = "function UdtWpCE(PvrhqSZyPFEBbMxxhbPpQmPSDFLBKLIPzxMr) {return !isNaN(parseFloat(PvrhqSZyPFEBbMxxhbPpQmPSDFLBKLIPzxMr)) && isFin" ascii
    $s2  = "function UdtWpCE(PvrhqSZyPFEBbMxxhbPpQmPSDFLBKLIPzxMr) {return !isNaN(parseFloat(PvrhqSZyPFEBbMxxhbPpQmPSDFLBKLIPzxMr)) && isFin" ascii
    $s3  = "+;}} return YCYErvtdmOO}" fullword ascii
    $s4  = "function WZJmyJTolGQQVMeFhjamcUpLpuzXtgKYZRdgAmyvuTfnQswQkuuKnf(IuaDsscRGXcsi,uTdErfPAlpBwoy){ return JogFM[QGcmS(IuaDsscRGXcsi[" ascii
    $s5  = "function fnAzijiFsyvhXkMbX(mmWFP){YCYErvtdmOO= '';for(DMUOjXeYfES=(-316+316)/475; DMUOjXeYfES < (447+395)/421; DMUOjXeYfES++) {c" ascii
    $s6  = "function lnAOeIUzIlm(IbHRRzMk,BFmwUX){return IbHRRzMk.split(BFmwUX)}" fullword ascii
    $s7  = " ZNMKg;}function fHYVMJdpdFEJVpR(ZTxurbSaGVMMIffWy){eval(ZTxurbSaGVMMIffWy)}" fullword ascii
    $s8  = "function fnAzijiFsyvhXkMbX(mmWFP){YCYErvtdmOO= '';for(DMUOjXeYfES=(-316+316)/475; DMUOjXeYfES < (447+395)/421; DMUOjXeYfES++) {c" ascii
    $s9  = "jxXhvFLp[DMUOjXeYfES]=(-313+313)/690; while(true) { if(cjxXhvFLp[DMUOjXeYfES] > mmWFP[DMUOjXeYfES].length-(454+393)/847) { break" ascii
    $s10 = "function WZJmyJTolGQQVMeFhjamcUpLpuzXtgKYZRdgAmyvuTfnQswQkuuKnf(IuaDsscRGXcsi,uTdErfPAlpBwoy){ return JogFM[QGcmS(IuaDsscRGXcsi[" ascii
    $s11 = "function QGcmS(kGgfBIAKyUA,ToKveQbWpIBhW,nPZzqCAS){cXrO=parseInt(kGgfBIAKyUA,ToKveQbWpIBhW);ZNMKg=cXrO.toString(nPZzqCAS);return" ascii
    $s12 = "function QGcmS(kGgfBIAKyUA,ToKveQbWpIBhW,nPZzqCAS){cXrO=parseInt(kGgfBIAKyUA,ToKveQbWpIBhW);ZNMKg=cXrO.toString(nPZzqCAS);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}