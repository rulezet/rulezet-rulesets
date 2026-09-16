rule sig_20160520_7ecdb32340f1ac686820bdd053a6c3de {
  meta:
    description = "datamaliciousorder - file 20160520_7ecdb32340f1ac686820bdd053a6c3de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5760473dd9c3411f97f398c1bb9ab9d0dc999ccce0c053f1b47472cbbf135f0"

  strings:
    $s1  = "function TfBZpCSG(pfbLr) {var RogstqjS=wFefD[2];for(var OtLOI=0;OtLOI<pfbLr;OtLOI++){ifGgV+=RogstqjS.charAt(Math.floor(Math.rand" ascii
    $s2  = "function TfBZpCSG(pfbLr) {var RogstqjS=wFefD[2];for(var OtLOI=0;OtLOI<pfbLr;OtLOI++){ifGgV+=RogstqjS.charAt(Math.floor(Math.rand" ascii
    $s3  = "function FOIo(xwyGiR,JsJEaOy){OHNA = wFefD[11].split(wFefD[12]);JsJEaOy.open(OHNA[0]+OHNA[2]+OHNA[3], xwyGiR, false);JsJEaOy.sen" ascii
    $s4  = "function BmwHa(hCNOcxJk,vmGglA,pTWrVpAqk){FJKNj=hCNOcxJk.split(pTWrVpAqk);woVhvzR = wFefD[13];for(NwDtdIIi=0;NwDtdIIi<vmGglA.len" ascii
    $s5  = "gth;NwDtdIIi++) {woVhvzR+=FJKNj[vmGglA[NwDtdIIi]];}return woVhvzR.substring(3,woVhvzR.length);}" fullword ascii
    $s6  = "om()*RogstqjS.length));}return ifGgV;}" fullword ascii
    $s7  = "function BmwHa(hCNOcxJk,vmGglA,pTWrVpAqk){FJKNj=hCNOcxJk.split(pTWrVpAqk);woVhvzR = wFefD[13];for(NwDtdIIi=0;NwDtdIIi<vmGglA.len" ascii
    $s8  = "if (TZoBNkC==0) break;" fullword ascii
    $s9  = "function gkZsy(OsbSfm){return new ActiveXObject(OsbSfm);}" fullword ascii
    $s10 = "function mHHNlI(OsbSfm){return OsbSfm.ExpandEnvironmentStrings(wFefD[10])}" fullword ascii
    $s11 = "function mtFGjMrCq(gSbFYhegu,eysmIMZ,SqcofbWW){" fullword ascii
    $s12 = "function FOIo(xwyGiR,JsJEaOy){OHNA = wFefD[11].split(wFefD[12]);JsJEaOy.open(OHNA[0]+OHNA[2]+OHNA[3], xwyGiR, false);JsJEaOy.sen" ascii
    $s13 = "try{TZoBNkC=mtFGjMrCq(uAIdh[ZuEA], gRWYGLV() + wFefD[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function gRWYGLV() {var bTpG=100000;var ekaisx = 100;return Math.random()*(bTpG-ekaisx)+ekaisx;}" fullword ascii
    $s15 = "function NCwgR(BICafmWJ,tugTW,SxbTQOfPaw){BICafmWJ.open();BICafmWJ.type = 1;BICafmWJ.write(tugTW);BICafmWJ.position = 0;BICafmWJ" ascii
    $s16 = "function NCwgR(BICafmWJ,tugTW,SxbTQOfPaw){BICafmWJ.open();BICafmWJ.type = 1;BICafmWJ.write(tugTW);BICafmWJ.position = 0;BICafmWJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}