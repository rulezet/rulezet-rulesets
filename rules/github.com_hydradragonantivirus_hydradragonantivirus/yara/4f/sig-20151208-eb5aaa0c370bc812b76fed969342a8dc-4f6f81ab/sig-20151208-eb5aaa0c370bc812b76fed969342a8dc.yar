rule sig_20151208_eb5aaa0c370bc812b76fed969342a8dc {
  meta:
    description = "datamaliciousorder - file 20151208_eb5aaa0c370bc812b76fed969342a8dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81555e2e8d5716f38b9f1d89225aa71fdaf2bb291e1e5ca1b61d5e99a2a6b23a"

  strings:
    $s1  = "function MxLesvN(FZJqwSbzEaVMqAOUWxAwIHRauEfQgdTNwbKY) {return !isNaN(parseFloat(FZJqwSbzEaVMqAOUWxAwIHRauEfQgdTNwbKY)) && isFin" ascii
    $s2  = "function MxLesvN(FZJqwSbzEaVMqAOUWxAwIHRauEfQgdTNwbKY) {return !isNaN(parseFloat(FZJqwSbzEaVMqAOUWxAwIHRauEfQgdTNwbKY)) && isFin" ascii
    $s3  = "push(\"32\");f.push(\"80\");f.push(\"83\");f.push(\"89\");f.push(\"32\");f.push(\"61\");f.push(\"32\");f.push(\"110\");f.push(\"" ascii
    $s4  = "function drtubbGjbho(JldizvHK,aiQXgF){return JldizvHK.split(aiQXgF)}" fullword ascii
    $s5  = "var xTspAUMcNZcUf=[];for(fzohNUR=(-397+397)/580;fzohNUR<(67967+769)/537;fzohNUR++){xTspAUMcNZcUf[fzohNUR]=String.fromCharCode(fz" ascii
    $s6  = "push(\"118\");f.push(\"97\");f.push(\"114\");f.push(\"32\");f.push(\"108\");f.push(\"114\");f.push(\"32\");f.push(\"61\");f.push" ascii
    $s7  = "push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"125\");e.push(\"59\");e.push(\"32\");e.push(\"" ascii
    $s8  = "function yLRTxnbjTFhCERDOn(ptOfi){UrkaAOsVncv= '';for(TsHmKWjPYoS=(-312+312)/364; TsHmKWjPYoS < (743+235)/489; TsHmKWjPYoS++) {R" ascii
    $s9  = "rQawoGIV[TsHmKWjPYoS]=(-142+142)/700; while(true) { if(RrQawoGIV[TsHmKWjPYoS] > ptOfi[TsHmKWjPYoS].length-(-95+714)/619) { break" ascii
    $s10 = "push(\"97\");e.push(\"46\");e.push(\"111\");e.push(\"112\");e.push(\"101\");e.push(\"110\");e.push(\"40\");e.push(\"112\");e.pus" ascii
    $s11 = "push(\"32\");e.push(\"61\");e.push(\"32\");e.push(\"48\");e.push(\"59\");e.push(\"13\");e.push(\"10\");e.push(\"32\");e.push(\"3" ascii
    $s12 = "push(\"97\");f.push(\"114\");f.push(\"32\");f.push(\"100\");f.push(\"108\");f.push(\"101\");f.push(\"106\");f.push(\"116\");f.pu" ascii
    $s13 = "function YRFmAMCIUQSNyaDbzebhPYxErDsqfmTfyScOIMQFVvodwkXYexaEyT(oxmwSOAIYsnnk,mwPpWhFuMfXPtg){ return xTspAUMcNZcUf[usiMY(oxmwSO" ascii
    $s14 = "function YRFmAMCIUQSNyaDbzebhPYxErDsqfmTfyScOIMQFVvodwkXYexaEyT(oxmwSOAIYsnnk,mwPpWhFuMfXPtg){ return xTspAUMcNZcUf[usiMY(oxmwSO" ascii
    $s15 = "push(\"72\");f.push(\"34\");f.push(\"59\");f.push(\"13\");f.push(\"10\");f.push(\"118\");f.push(\"97\");f.push(\"114\");f.push(" ascii
    $s16 = "return UrkaAOsVncv}" fullword ascii
    $s17 = "ohNUR)}function usiMY(ZttQaqDeVZx,LBbgTheMwvjjj,uvqyTESC){bMfk=parseInt(ZttQaqDeVZx,LBbgTheMwvjjj);zjapb=bMfk.toString(uvqyTESC)" ascii
    $s18 = ";return zjapb;}function RBuHYgdwpKmeWcO(ItoTCRREoCDpRkhTA){eval(ItoTCRREoCDpRkhTA)}" fullword ascii
    $s19 = "push(\"71\");f.push(\"68\");f.push(\"32\");f.push(\"61\");f.push(\"32\");f.push(\"34\");f.push(\"65\");f.push(\"68\");f.push(\"7" ascii
    $s20 = "function yLRTxnbjTFhCERDOn(ptOfi){UrkaAOsVncv= '';for(TsHmKWjPYoS=(-312+312)/364; TsHmKWjPYoS < (743+235)/489; TsHmKWjPYoS++) {R" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}