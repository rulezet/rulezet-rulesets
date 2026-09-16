rule sig_20151209_cafea64f14a5f000fc8a795527e11356 {
  meta:
    description = "datamaliciousorder - file 20151209_cafea64f14a5f000fc8a795527e11356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d387903ad9550f5b8f3a14d62a4eb6216405045ec9ebca2750d6bf2b04400ef4"

  strings:
    $s1  = " ShLOg;}function TWfKeBSbEotvejx(QoKnzZzrhuFVVthTx){eval(QoKnzZzrhuFVVthTx)}" fullword ascii
    $s2  = "function PuzxoEk(jvEunqEygVBhLUzcqGqGmVjXfXxzurTDdpzK) {return !isNaN(parseFloat(jvEunqEygVBhLUzcqGqGmVjXfXxzurTDdpzK)) && isFin" ascii
    $s3  = "function PuzxoEk(jvEunqEygVBhLUzcqGqGmVjXfXxzurTDdpzK) {return !isNaN(parseFloat(jvEunqEygVBhLUzcqGqGmVjXfXxzurTDdpzK)) && isFin" ascii
    $s4  = "function NSmio(xcaqBRmsNyn,ksqlpotXMNBBN,BdeuvTjr){dGSx=parseInt(xcaqBRmsNyn,ksqlpotXMNBBN);ShLOg=dGSx.toString(BdeuvTjr);return" ascii
    $s5  = "function NSmio(xcaqBRmsNyn,ksqlpotXMNBBN,BdeuvTjr){dGSx=parseInt(xcaqBRmsNyn,ksqlpotXMNBBN);ShLOg=dGSx.toString(BdeuvTjr);return" ascii
    $s6  = "+;}} return JJwBoGhqViJ}" fullword ascii
    $s7  = "aVkOKfvgn[bBLNGtrSvbX]=(-129+129)/411; while(true) { if(aVkOKfvgn[bBLNGtrSvbX] > UyMdR[bBLNGtrSvbX].length-(601+304)/905) { brea" ascii
    $s8  = "function CFkTbuFJZefZMetUAbXieBjrYmTLsRVtZGJxCXvALiQbYWDBwTdTab(vstMtndCwyDzK,nGGzDTPckevncS){ return qWDEi[NSmio(vstMtndCwyDzK[" ascii
    $s9  = "function fQjMlNDkgqi(fODCQabC,pBeAKw){return fODCQabC.split(pBeAKw)}" fullword ascii
    $s10 = "function CFkTbuFJZefZMetUAbXieBjrYmTLsRVtZGJxCXvALiQbYWDBwTdTab(vstMtndCwyDzK,nGGzDTPckevncS){ return qWDEi[NSmio(vstMtndCwyDzK[" ascii
    $s11 = "function btBVPVcuvkValqEsk(UyMdR){JJwBoGhqViJ= '';for(bBLNGtrSvbX=(-794+794)/964; bBLNGtrSvbX < (1124+678)/901; bBLNGtrSvbX++) {" ascii
    $s12 = "function btBVPVcuvkValqEsk(UyMdR){JJwBoGhqViJ= '';for(bBLNGtrSvbX=(-794+794)/964; bBLNGtrSvbX < (1124+678)/901; bBLNGtrSvbX++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}