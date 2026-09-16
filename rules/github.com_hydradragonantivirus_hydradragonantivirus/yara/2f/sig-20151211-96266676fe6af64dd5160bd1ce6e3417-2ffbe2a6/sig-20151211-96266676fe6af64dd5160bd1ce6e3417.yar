rule sig_20151211_96266676fe6af64dd5160bd1ce6e3417 {
  meta:
    description = "datamaliciousorder - file 20151211_96266676fe6af64dd5160bd1ce6e3417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4601a5f3a29d1a5350fcf0dd6f25454bca754d9aa09a119b16af7010ffa58b1f"

  strings:
    $s1  = "function RnOEQtO(eTEIeuiIikbSWwXtKMFGVyuKjEjHZCNFRRFc) {return !isNaN(parseFloat(eTEIeuiIikbSWwXtKMFGVyuKjEjHZCNFRRFc)) && isFin" ascii
    $s2  = "function RnOEQtO(eTEIeuiIikbSWwXtKMFGVyuKjEjHZCNFRRFc) {return !isNaN(parseFloat(eTEIeuiIikbSWwXtKMFGVyuKjEjHZCNFRRFc)) && isFin" ascii
    $s3  = "function olaKcxGAbav(UbdFkyHq,sOmVxr){return UbdFkyHq.split(sOmVxr)}" fullword ascii
    $s4  = "var d=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"59\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "function uaQxnzflanxvQgfWy(sYHAe){jhuyyIeFzJs= '';UoJTdkkzZhf=(-167+167)/18; while(true){if(UoJTdkkzZhf >= (-258+678)/210)break;" ascii
    $s6  = "var x=new Array(\"2d\",\"2d\",\"2c\",\"29\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s7  = "eykLIRVhP[UoJTdkkzZhf]=(-103+103)/197; while(true) { if(eykLIRVhP[UoJTdkkzZhf] > sYHAe[UoJTdkkzZhf].length-(-438+861)/423) { bre" ascii
    $s8  = "function uaQxnzflanxvQgfWy(sYHAe){jhuyyIeFzJs= '';UoJTdkkzZhf=(-167+167)/18; while(true){if(UoJTdkkzZhf >= (-258+678)/210)break;" ascii
    $s9  = "function xXGFJ(JlDdlGLrxba,kqrrGgjiLOlZq,naoTGXWw){GIAS=parseInt(JlDdlGLrxba,kqrrGgjiLOlZq);gFIcO=GIAS.toString(naoTGXWw);return" ascii
    $s10 = "++;}UoJTdkkzZhf++;} return jhuyyIeFzJs}" fullword ascii
    $s11 = "function wYNTfVFrTGNZZzpPTMkFgEBxoNEHXQCnjBMgyUIasASiSOODEdufZO(FuxYTgeEFnobV,gGqnTpEbNxGmIt){ return pmfOn[xXGFJ(FuxYTgeEFnobV[" ascii
    $s12 = "var d=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"59\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = " gFIcO;}function lQVkEVtfBXrMJdd(FLICDTnhdorfZYlle){eval(FLICDTnhdorfZYlle)}" fullword ascii
    $s14 = "function wYNTfVFrTGNZZzpPTMkFgEBxoNEHXQCnjBMgyUIasASiSOODEdufZO(FuxYTgeEFnobV,gGqnTpEbNxGmIt){ return pmfOn[xXGFJ(FuxYTgeEFnobV[" ascii
    $s15 = "function xXGFJ(JlDdlGLrxba,kqrrGgjiLOlZq,naoTGXWw){GIAS=parseInt(JlDdlGLrxba,kqrrGgjiLOlZq);gFIcO=GIAS.toString(naoTGXWw);return" ascii
    $s16 = "var x=new Array(\"2d\",\"2d\",\"2c\",\"29\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}