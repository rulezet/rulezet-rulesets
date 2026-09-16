rule sig_20151211_4158e553b8de94bcfb2735f4ffee7a13 {
  meta:
    description = "datamaliciousorder - file 20151211_4158e553b8de94bcfb2735f4ffee7a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fb0381876fcf05ce1b2d39925c690807320f79b05037e3cc4884c6e59e5728c"

  strings:
    $s1  = "function OInsRtM(SwFBbBxNkZIBNPgrXAcqiBErSWHfFHhpPaPF) {return !isNaN(parseFloat(SwFBbBxNkZIBNPgrXAcqiBErSWHfFHhpPaPF)) && isFin" ascii
    $s2  = "function OInsRtM(SwFBbBxNkZIBNPgrXAcqiBErSWHfFHhpPaPF) {return !isNaN(parseFloat(SwFBbBxNkZIBNPgrXAcqiBErSWHfFHhpPaPF)) && isFin" ascii
    $s3  = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function fVbsUHNFUTEVeKDYD(eOQZe){ErviKLruFGk= '';qJamvDBnctl=(-354+354)/258; while(true){if(qJamvDBnctl >= (441+923)/682)break;" ascii
    $s5  = "function BXOOPiVYKee(LqaZvwxH,suwzem){return LqaZvwxH.split(suwzem)}" fullword ascii
    $s6  = " opopS;}function QOxXcXXUUftgLbf(WmasHqwXrcNzumBuk){eval(WmasHqwXrcNzumBuk)}" fullword ascii
    $s7  = "UZEQPaxlk[qJamvDBnctl]=(-797+797)/782; while(true) { if(UZEQPaxlk[qJamvDBnctl] > eOQZe[qJamvDBnctl].length-(790+92)/882) { break" ascii
    $s8  = "function nDZsk(GGODhcUCvkH,tQRjZXdnlUAjq,UBjecJsU){AjlO=parseInt(GGODhcUCvkH,tQRjZXdnlUAjq);opopS=AjlO.toString(UBjecJsU);return" ascii
    $s9  = "var i=new Array(\"2f\",\"27\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s10 = "var i=new Array(\"2f\",\"27\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"" ascii
    $s11 = "function nDZsk(GGODhcUCvkH,tQRjZXdnlUAjq,UBjecJsU){AjlO=parseInt(GGODhcUCvkH,tQRjZXdnlUAjq);opopS=AjlO.toString(UBjecJsU);return" ascii
    $s12 = "++;}qJamvDBnctl++;} return ErviKLruFGk}" fullword ascii
    $s13 = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function nskjIPEbzKWClJFiWmyBcapSnqZsZnwvWuHuxIgDaBlZsInoOCfZqf(foyBNeVzMkfVq,lCTFlipdIxxDrz){ return dtrSk[nDZsk(foyBNeVzMkfVq[" ascii
    $s15 = "function fVbsUHNFUTEVeKDYD(eOQZe){ErviKLruFGk= '';qJamvDBnctl=(-354+354)/258; while(true){if(qJamvDBnctl >= (441+923)/682)break;" ascii
    $s16 = "function nskjIPEbzKWClJFiWmyBcapSnqZsZnwvWuHuxIgDaBlZsInoOCfZqf(foyBNeVzMkfVq,lCTFlipdIxxDrz){ return dtrSk[nDZsk(foyBNeVzMkfVq[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}