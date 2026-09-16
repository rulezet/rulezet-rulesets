rule sig_20151208_de39a55f750a1a67a24832bc092183d6 {
  meta:
    description = "datamaliciousorder - file 20151208_de39a55f750a1a67a24832bc092183d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac3aa69784cc01d796ac76a8c4d28c03de3e7cc1cab012dc3a61def0a37652d5"

  strings:
    $s1  = "function yJnUHSC(zOHyxiGJbYnfZvTxwXnKBnOFSByCygkeMIgh) {return !isNaN(parseFloat(zOHyxiGJbYnfZvTxwXnKBnOFSByCygkeMIgh)) && isFin" ascii
    $s2  = "function yJnUHSC(zOHyxiGJbYnfZvTxwXnKBnOFSByCygkeMIgh) {return !isNaN(parseFloat(zOHyxiGJbYnfZvTxwXnKBnOFSByCygkeMIgh)) && isFin" ascii
    $s3  = "push(\"98\");y.push(\"114\");y.push(\"101\");y.push(\"97\");y.push(\"107\");y.push(\"59\");y.push(\"13\");y.push(\"10\");y.push(" ascii
    $s4  = "push(\"59\");y.push(\"32\");y.push(\"13\");y.push(\"10\");y.push(\"9\");y.push(\"9\");y.push(\"32\");y.push(\"32\");y.push(\"32" ascii
    $s5  = "function iePXmXgNApgPfimRK(BsHDY){cIraIpmGsYk= '';for(TlmwpyqoTIC=(-85+85)/942; TlmwpyqoTIC < (-468+572)/52; TlmwpyqoTIC++) {BhY" ascii
    $s6  = "push(\"114\");g.push(\"32\");g.push(\"74\");g.push(\"122\");g.push(\"117\");g.push(\"98\");g.push(\"82\");g.push(\"71\");g.push(" ascii
    $s7  = ";return ylewu;}function RpjZUwsvUXKZZmH(eDNuLaliJvdalJaAR){eval(eDNuLaliJvdalJaAR)}" fullword ascii
    $s8  = "KRMjRn[TlmwpyqoTIC]=(-721+721)/1; while(true) { if(BhYKRMjRn[TlmwpyqoTIC] > BsHDY[TlmwpyqoTIC].length-(-18+945)/927) { break; } " ascii
    $s9  = "push(\"87\");g.push(\"83\");g.push(\"99\");g.push(\"114\");g.push(\"105\");g.push(\"34\");g.push(\"58\");g.push(\"34\");g.push(" ascii
    $s10 = "push(\"59\");g.push(\"13\");g.push(\"10\");g.push(\"118\");g.push(\"97\");g.push(\"114\");g.push(\"32\");g.push(\"101\");g.push(" ascii
    $s11 = "turn cIraIpmGsYk}" fullword ascii
    $s12 = "var DqXICKvhkQzaf=[];for(AFKwZtY=(-904+904)/163;AFKwZtY<(79861+523)/628;AFKwZtY++){DqXICKvhkQzaf[AFKwZtY]=String.fromCharCode(AF" ascii
    $s13 = "push(\"10\");g.push(\"118\");g.push(\"97\");g.push(\"114\");g.push(\"32\");g.push(\"102\");g.push(\"118\");g.push(\"77\");g.push" ascii
    $s14 = "function CsJwQPbqeXP(qXtEqBcg,RyjzSE){return qXtEqBcg.split(RyjzSE)}" fullword ascii
    $s15 = "function lZSLPfiWjQmmRWBlsZVxXxyVeMfUePcZhqgLPaOKDEBJAPjGJEAckK(GkQaIwxnQMrND,YLjmDtuSmanFIx){ return DqXICKvhkQzaf[VRJGR(GkQaIw" ascii
    $s16 = "KwZtY)}function VRJGR(VavYnfRiZiJ,eQegGWCsSHAyh,HlnlJneP){yhon=parseInt(VavYnfRiZiJ,eQegGWCsSHAyh);ylewu=yhon.toString(HlnlJneP)" ascii
    $s17 = "function iePXmXgNApgPfimRK(BsHDY){cIraIpmGsYk= '';for(TlmwpyqoTIC=(-85+85)/942; TlmwpyqoTIC < (-468+572)/52; TlmwpyqoTIC++) {BhY" ascii
    $s18 = "push(\"59\");y.push(\"9\");y.push(\"32\");y.push(\"13\");y.push(\"10\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32" ascii
    $s19 = "push(\"122\");y.push(\"117\");y.push(\"98\");y.push(\"82\");y.push(\"71\");y.push(\"101\");y.push(\"43\");y.push(\"34\");y.push(" ascii
    $s20 = "push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"32\");y.push(\"102\");y.push(\"118\");y.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}