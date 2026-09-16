rule sig_20151211_1a02e50c9c4ef354787edc48eaccaa2d {
  meta:
    description = "datamaliciousorder - file 20151211_1a02e50c9c4ef354787edc48eaccaa2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523c5ba0c3171437cc482257d277fc95b3c233ee2f824482f8f903decfb16775"

  strings:
    $s1  = "function mJmZVSJ(nUKxYtDWnbOZCrEJcHrurMllmSvgxLiQokXv) {return !isNaN(parseFloat(nUKxYtDWnbOZCrEJcHrurMllmSvgxLiQokXv)) && isFin" ascii
    $s2  = "function mJmZVSJ(nUKxYtDWnbOZCrEJcHrurMllmSvgxLiQokXv) {return !isNaN(parseFloat(nUKxYtDWnbOZCrEJcHrurMllmSvgxLiQokXv)) && isFin" ascii
    $s3  = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function XSNlL(BemiNEUinKr,McblXHdVQxwwy,zPcxkDgq){pswj=parseInt(BemiNEUinKr,McblXHdVQxwwy);lUvRQ=pswj.toString(zPcxkDgq);return" ascii
    $s5  = "function XSNlL(BemiNEUinKr,McblXHdVQxwwy,zPcxkDgq){pswj=parseInt(BemiNEUinKr,McblXHdVQxwwy);lUvRQ=pswj.toString(zPcxkDgq);return" ascii
    $s6  = "function HfzhZBrLmDG(uofymQVx,SASfeq){return uofymQVx.split(SASfeq)}" fullword ascii
    $s7  = "var f=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "var y=new Array(\"2e\",\"2a\",\"2f\",\"29\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s9  = "++;}PTSsTYahBLP++;} return mPjSBvVCOPy}" fullword ascii
    $s10 = " lUvRQ;}function AvLTVqhoTtnnEEd(aNTIxNVkfPjerXQVy){eval(aNTIxNVkfPjerXQVy)}" fullword ascii
    $s11 = "var y=new Array(\"2e\",\"2a\",\"2f\",\"29\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = "function FuUTbqGODDVRtSvdutpEuVLVItWsTBESAykfGuCzlyqEeiDsxruPRI(sMsTyQxKZYGaJ,gLEWADFtMEfyrw){ return tjSZY[XSNlL(sMsTyQxKZYGaJ[" ascii
    $s13 = "function ImCVUlxuWSRfFxiwh(wRVvJ){mPjSBvVCOPy= '';PTSsTYahBLP=(-359+359)/458; while(true){if(PTSsTYahBLP >= (122+832)/477)break;" ascii
    $s14 = "yDGVAhdLo[PTSsTYahBLP]=(-442+442)/866; while(true) { if(yDGVAhdLo[PTSsTYahBLP] > wRVvJ[PTSsTYahBLP].length-(-444+757)/313) { bre" ascii
    $s15 = "function FuUTbqGODDVRtSvdutpEuVLVItWsTBESAykfGuCzlyqEeiDsxruPRI(sMsTyQxKZYGaJ,gLEWADFtMEfyrw){ return tjSZY[XSNlL(sMsTyQxKZYGaJ[" ascii
    $s16 = "function ImCVUlxuWSRfFxiwh(wRVvJ){mPjSBvVCOPy= '';PTSsTYahBLP=(-359+359)/458; while(true){if(PTSsTYahBLP >= (122+832)/477)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}