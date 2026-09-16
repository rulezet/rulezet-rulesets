rule sig_20151209_672c6a24918ac4baa25ef7b1ce87f2f0 {
  meta:
    description = "datamaliciousorder - file 20151209_672c6a24918ac4baa25ef7b1ce87f2f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5baa847ac7f0b0b641d3e803ff5bb9d1a8702b8521e0e72e03136593b1df287"

  strings:
    $s1  = "function lrdswmA(GkYrLEmjdLMdmBBQEPSqzpwoHYqhFquKroHU) {return !isNaN(parseFloat(GkYrLEmjdLMdmBBQEPSqzpwoHYqhFquKroHU)) && isFin" ascii
    $s2  = "function lrdswmA(GkYrLEmjdLMdmBBQEPSqzpwoHYqhFquKroHU) {return !isNaN(parseFloat(GkYrLEmjdLMdmBBQEPSqzpwoHYqhFquKroHU)) && isFin" ascii
    $s3  = "function twWDjbSyyfQbqjhFw(lnydz){zpxJixxkYJt= '';for(AWYdYdVUdSl=(-362+362)/726; AWYdYdVUdSl < (467+815)/641; AWYdYdVUdSl++) {A" ascii
    $s4  = "function twWDjbSyyfQbqjhFw(lnydz){zpxJixxkYJt= '';for(AWYdYdVUdSl=(-362+362)/726; AWYdYdVUdSl < (467+815)/641; AWYdYdVUdSl++) {A" ascii
    $s5  = "function nmeFTlhxZXfVblGvQskxgKzfJXsDQliAiizmuYnMMdQwAckOVFzBKX(ezxieYCsJOCWR,XkUkReYxBDExRg){ return LHkLe[MXFZy(ezxieYCsJOCWR[" ascii
    $s6  = " bhJOZ;}function NwBNTSeJKBwIRVB(lYipGqinjhWKHzqaU){eval(lYipGqinjhWKHzqaU)}" fullword ascii
    $s7  = "function nmeFTlhxZXfVblGvQskxgKzfJXsDQliAiizmuYnMMdQwAckOVFzBKX(ezxieYCsJOCWR,XkUkReYxBDExRg){ return LHkLe[MXFZy(ezxieYCsJOCWR[" ascii
    $s8  = "}} return zpxJixxkYJt}" fullword ascii
    $s9  = "function MXFZy(WKOzQtaKgpv,hUuIKShcGltVh,bGWTnVCQ){Fgdo=parseInt(WKOzQtaKgpv,hUuIKShcGltVh);bhJOZ=Fgdo.toString(bGWTnVCQ);return" ascii
    $s10 = "function MXFZy(WKOzQtaKgpv,hUuIKShcGltVh,bGWTnVCQ){Fgdo=parseInt(WKOzQtaKgpv,hUuIKShcGltVh);bhJOZ=Fgdo.toString(bGWTnVCQ);return" ascii
    $s11 = "function NBuBryojuhC(PnMMkYCp,wZFAiS){return PnMMkYCp.split(wZFAiS)}" fullword ascii
    $s12 = "tuJupCdw[AWYdYdVUdSl]=(-74+74)/122; while(true) { if(AtuJupCdw[AWYdYdVUdSl] > lnydz[AWYdYdVUdSl].length-(140+140)/280) { break; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}