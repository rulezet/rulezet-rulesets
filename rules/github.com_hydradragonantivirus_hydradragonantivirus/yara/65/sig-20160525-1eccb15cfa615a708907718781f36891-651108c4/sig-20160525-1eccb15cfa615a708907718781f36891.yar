rule sig_20160525_1eccb15cfa615a708907718781f36891 {
  meta:
    description = "datamaliciousorder - file 20160525_1eccb15cfa615a708907718781f36891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7c750b573587fe5cbb92d62fe20371cef9a68d0683d25adf9fab268ce0e32fa"

  strings:
    $s1  = ".pow(Math.cos(75), 2) - 1))-141)) yJuQhHuDkmdWuPZEXcFGY += zXwbqKYVIPGmeGVNmlKjl(ehJSAwxKx, VBkdDILzlxNyZZeYa);else yJuQhHuDkmdW" ascii
    $s2  = ", 2) - 1))-108)) yJuQhHuDkmdWuPZEXcFGY += Mq(ehJSAwxKx);else if (cwGWwcAn == (205 + Math.round((Math.pow(Math.sin(75), 2) + Math" ascii
    $s3  = "function tIJlNHbTe(SGRQRhRUKqrqv) {var pmsJEsylAGlEQ = LhtDBApHYRQSSmPlw.join(WvqvrfnYoNkkQRjQFmTStR[0]);var ehJSAwxKx, VBkdDILz" ascii
    $s4  = "function lamYjzBOaRtmHO(DOeEZmZKT,fxFXoxzvBWdWI){return DOeEZmZKT.charAt(fxFXoxzvBWdWI);}" fullword ascii
    $s5  = "YmI(pmsJEsylAGlEQ,lamYjzBOaRtmHO(SGRQRhRUKqrqv,sjIesGKOzjfRSgyf++));uxSGXj = bQmKMtMbpuRQpPAEkJHClmbC<< (868 + Math.round((Math." ascii
    $s6  = "uPZEXcFGY += tlAngAnPtvaETbiPiFO(ehJSAwxKx, VBkdDILzlxNyZZeYa, fZvPqXS);} while (sjIesGKOzjfRSgyf < SGRQRhRUKqrqv.length);return" ascii
    $s7  = "function jLQTzBkeebPHyyNYmI(OCnhbAYOVZmQlfkkt,zyUpdqKq){return OCnhbAYOVZmQlfkkt.indexOf(zyUpdqKq);}" fullword ascii
    $s8  = "function tIJlNHbTe(SGRQRhRUKqrqv) {var pmsJEsylAGlEQ = LhtDBApHYRQSSmPlw.join(WvqvrfnYoNkkQRjQFmTStR[0]);var ehJSAwxKx, VBkdDILz" ascii
    $s9  = "function Mq(oZsfQCZJaCioVuFaTEILaOnC){return String.fromCharCode(oZsfQCZJaCioVuFaTEILaOnC);}" fullword ascii
    $s10 = "function tlAngAnPtvaETbiPiFO(mbyclE,DyAtU,LzaQzUlYFuf){return String.fromCharCode(mbyclE,DyAtU,LzaQzUlYFuf);}" fullword ascii
    $s11 = "function zXwbqKYVIPGmeGVNmlKjl(DnXHADoc,OzosUCYLO){return String.fromCharCode(DnXHADoc,OzosUCYLO);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}