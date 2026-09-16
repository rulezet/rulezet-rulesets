rule sig_20151209_e2dc147a0f30c0397b17ccba5712a18a {
  meta:
    description = "datamaliciousorder - file 20151209_e2dc147a0f30c0397b17ccba5712a18a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41bc9b82ecf09483a6a4961d325d51c1537c5f64c8d4fb2a5c7dde9dbaaa7519"

  strings:
    $s1  = "function UBQUZeL(PYpwVrfmqbpASqeSeOahWJawIdbpwbrGZRkw) {return !isNaN(parseFloat(PYpwVrfmqbpASqeSeOahWJawIdbpwbrGZRkw)) && isFin" ascii
    $s2  = "function UBQUZeL(PYpwVrfmqbpASqeSeOahWJawIdbpwbrGZRkw) {return !isNaN(parseFloat(PYpwVrfmqbpASqeSeOahWJawIdbpwbrGZRkw)) && isFin" ascii
    $s3  = "function bzHyPuWHlImnhMQJX(lirAH){gbQiIrcAMTn= '';for(fydsXWpWegO=(-52+52)/709; fydsXWpWegO < (57+855)/456; fydsXWpWegO++) {RGvR" ascii
    $s4  = " return gbQiIrcAMTn}" fullword ascii
    $s5  = "function bzHyPuWHlImnhMQJX(lirAH){gbQiIrcAMTn= '';for(fydsXWpWegO=(-52+52)/709; fydsXWpWegO < (57+855)/456; fydsXWpWegO++) {RGvR" ascii
    $s6  = "kUHPO[fydsXWpWegO]=(-777+777)/16; while(true) { if(RGvRkUHPO[fydsXWpWegO] > lirAH[fydsXWpWegO].length-(-74+341)/267) { break; } " ascii
    $s7  = "function PlDsSMbeXmR(tgjIqzWl,XsyZYo){return tgjIqzWl.split(XsyZYo)}" fullword ascii
    $s8  = ";return LcyTh;}function nnhQwYWYyWlsbIo(yeBsWXotNgQJGNBkh){eval(yeBsWXotNgQJGNBkh)}" fullword ascii
    $s9  = "push(\"10\");C.push(\"32\");C.push(\"32\");C.push(\"99\");C.push(\"97\");C.push(\"116\");C.push(\"99\");C.push(\"104\");C.push(" ascii
    $s10 = "push(\"67\");C.push(\"52\");C.push(\"42\");C.push(\"47\");C.push(\"34\");C.push(\"46\");C.push(\"101\");C.push(\"120\");C.push(" ascii
    $s11 = "push(\"59\");C.push(\"9\");C.push(\"32\");C.push(\"13\");C.push(\"10\");C.push(\"32\");C.push(\"32\");C.push(\"32\");C.push(\"32" ascii
    $s12 = "push(\"34\");o.push(\"88\");o.push(\"77\");o.push(\"76\");o.push(\"34\");o.push(\"43\");o.push(\"40\");o.push(\"50\");o.push(\"5" ascii
    $s13 = "function kqmUBxwiyCbfKKRFQXEJJJTMfZeqoXFDdxeJnnBhdmVESpZvMSkhaY(ZoxCXUFPgEQQb,xaImqYHwFFgHol){ return eUDAEpujQAxyF[OjUKK(ZoxCXU" ascii
    $s14 = "push(\"82\");C.push(\"120\");C.push(\"53\");C.push(\"50\");C.push(\"83\");C.push(\"102\");C.push(\"122\");C.push(\"78\");C.push(" ascii
    $s15 = "function kqmUBxwiyCbfKKRFQXEJJJTMfZeqoXFDdxeJnnBhdmVESpZvMSkhaY(ZoxCXUFPgEQQb,xaImqYHwFFgHol){ return eUDAEpujQAxyF[OjUKK(ZoxCXU" ascii
    $s16 = "LBcNs)}function OjUKK(GRllWIeOfVG,gNymvqzdfkmgA,bBdlVCjD){VCiE=parseInt(GRllWIeOfVG,gNymvqzdfkmgA);LcyTh=VCiE.toString(bBdlVCjD)" ascii
    $s17 = "var eUDAEpujQAxyF=[];for(sRLBcNs=(-368+368)/144;sRLBcNs<(87222+586)/686;sRLBcNs++){eUDAEpujQAxyF[sRLBcNs]=String.fromCharCode(sR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}