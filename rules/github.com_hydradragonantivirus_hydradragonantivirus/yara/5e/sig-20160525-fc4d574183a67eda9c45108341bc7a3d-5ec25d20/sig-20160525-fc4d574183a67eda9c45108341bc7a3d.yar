rule sig_20160525_fc4d574183a67eda9c45108341bc7a3d {
  meta:
    description = "datamaliciousorder - file 20160525_fc4d574183a67eda9c45108341bc7a3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350feffc1e0ff00a23d21e3ae9c76da5d093935c7983362c6432cf990e967d00"

  strings:
    $s1  = "function EbLxT(ScGGNIZnogzPg) {var upAdyDDkFTUPT = TvtTLIeGv.join(buabEZkMd[0]);var NLHEftFeIcq, iqsrxjMvwybSg, PEKqEuDJhbGCPAmO" ascii
    $s2  = "else if (jlYBaXvH == (798 + Math.round((Math.pow(Math.sin(486), 2) + Math.pow(Math.cos(486), 2) - 1))-734)) VGPqmdYoCmaJoijrEiF " ascii
    $s3  = "function hBgFoLjtWZmTzMVEXXICB(wIFEbDzbXGkgRjczTtUj,iDtFzsTxjrqepbkik){return wIFEbDzbXGkgRjczTtUj.charAt(iDtFzsTxjrqepbkik);}" fullword ascii
    $s4  = "function vImrGV(DtKrwLgUVJUL,fJMjEqbKmWBzM){return DtKrwLgUVJUL.indexOf(fJMjEqbKmWBzM);}" fullword ascii
    $s5  = "+= vykPaVOLv(NLHEftFeIcq, iqsrxjMvwybSg);else VGPqmdYoCmaJoijrEiF += vvwFaBUXQlqVy(NLHEftFeIcq, iqsrxjMvwybSg, PEKqEuDJhbGCPAmOW" ascii
    $s6  = "function vvwFaBUXQlqVy(YCOyeQeOxpLHzsqdKbjafx,HASpWGjGdGJBGH,GVYrMQPmKsGK){return String.fromCharCode(YCOyeQeOxpLHzsqdKbjafx,HAS" ascii
    $s7  = "function vykPaVOLv(SdMmnKtqmp,ECrUYdzJphWMfG){return String.fromCharCode(SdMmnKtqmp,ECrUYdzJphWMfG);}" fullword ascii
    $s8  = "function vvwFaBUXQlqVy(YCOyeQeOxpLHzsqdKbjafx,HASpWGjGdGJBGH,GVYrMQPmKsGK){return String.fromCharCode(YCOyeQeOxpLHzsqdKbjafx,HAS" ascii
    $s9  = "function EbLxT(ScGGNIZnogzPg) {var upAdyDDkFTUPT = TvtTLIeGv.join(buabEZkMd[0]);var NLHEftFeIcq, iqsrxjMvwybSg, PEKqEuDJhbGCPAmO" ascii
    $s10 = "yBzxGA);} while (azotrUHhEhJmpuXWln < ScGGNIZnogzPg.length);return VGPqmdYoCmaJoijrEiF;}" fullword ascii
    $s11 = "function l(EwIGknstz){return String.fromCharCode(EwIGknstz);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}