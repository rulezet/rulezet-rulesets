rule sig_20151209_3397530dae140e6090d8246296e66809 {
  meta:
    description = "datamaliciousorder - file 20151209_3397530dae140e6090d8246296e66809.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "427f876afd20331b8f3e9cf0040072db16e81a219c8fa0efa90ad31e55306baa"

  strings:
    $s1  = "function yghkhoAHNCPNaAasR(NWQYB){rOQbfhbcics= '';for(KVBCTkiIDUS=(-756+756)/861; KVBCTkiIDUS < (1324+278)/801; KVBCTkiIDUS++) {" ascii
    $s2  = "ThfOKjkPD[KVBCTkiIDUS]=(-609+609)/648; while(true) { if(ThfOKjkPD[KVBCTkiIDUS] > NWQYB[KVBCTkiIDUS].length-(-380+760)/380) { bre" ascii
    $s3  = "+;}} return rOQbfhbcics}" fullword ascii
    $s4  = "function LnPmv(IiQGNauRaKG,vvQYAbALhVDtn,SSNthxBb){cUgH=parseInt(IiQGNauRaKG,vvQYAbALhVDtn);FwKTo=cUgH.toString(SSNthxBb);return" ascii
    $s5  = "function eVQTXwaNQHOUwYBqlskTuKIYlxxkUAiUioZxEnedZhjZPYiVSVegOu(TubCjaaOKrGaX,GdoyoqEQGGhxAw){ return Ejmjk[LnPmv(TubCjaaOKrGaX[" ascii
    $s6  = "function EVNLKWIGHTk(pPnGEykY,CgtRYJ){return pPnGEykY.split(CgtRYJ)}" fullword ascii
    $s7  = "function LnPmv(IiQGNauRaKG,vvQYAbALhVDtn,SSNthxBb){cUgH=parseInt(IiQGNauRaKG,vvQYAbALhVDtn);FwKTo=cUgH.toString(SSNthxBb);return" ascii
    $s8  = "function yghkhoAHNCPNaAasR(NWQYB){rOQbfhbcics= '';for(KVBCTkiIDUS=(-756+756)/861; KVBCTkiIDUS < (1324+278)/801; KVBCTkiIDUS++) {" ascii
    $s9  = "function eVQTXwaNQHOUwYBqlskTuKIYlxxkUAiUioZxEnedZhjZPYiVSVegOu(TubCjaaOKrGaX,GdoyoqEQGGhxAw){ return Ejmjk[LnPmv(TubCjaaOKrGaX[" ascii
    $s10 = " FwKTo;}function hvwcQszUeFKLswA(GlJThDnzgIgxPgxXn){eval(GlJThDnzgIgxPgxXn)}" fullword ascii
    $s11 = "function lqAURrL(PHLotuLHVcaysNuwtjxWRlrdwtbOrjCWeWvn) {return !isNaN(parseFloat(PHLotuLHVcaysNuwtjxWRlrdwtbOrjCWeWvn)) && isFin" ascii
    $s12 = "function lqAURrL(PHLotuLHVcaysNuwtjxWRlrdwtbOrjCWeWvn) {return !isNaN(parseFloat(PHLotuLHVcaysNuwtjxWRlrdwtbOrjCWeWvn)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}