rule sig_20151211_9913dfef67adf395ba1d949597fd3908 {
  meta:
    description = "datamaliciousorder - file 20151211_9913dfef67adf395ba1d949597fd3908.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c63073ac1f8da28175e5d1d049a2f43324dd64b5192ebdba49eca8336ce8ee"

  strings:
    $s1  = "function xTtFzRI(gruohNAwrXVoRZjpKkQCeiKGeVVICviYaqfU) {return !isNaN(parseFloat(gruohNAwrXVoRZjpKkQCeiKGeVVICviYaqfU)) && isFin" ascii
    $s2  = "function xTtFzRI(gruohNAwrXVoRZjpKkQCeiKGeVVICviYaqfU) {return !isNaN(parseFloat(gruohNAwrXVoRZjpKkQCeiKGeVVICviYaqfU)) && isFin" ascii
    $s3  = "function LkduedouQdclpKtFP(cZjSu){aNMZZQMJJjC= '';HLGPQWKTFry=(-482+482)/285; while(true){if(HLGPQWKTFry >= (483+661)/572)break;" ascii
    $s4  = "mOZMFsDCN[HLGPQWKTFry]=(-924+924)/284; while(true) { if(mOZMFsDCN[HLGPQWKTFry] > cZjSu[HLGPQWKTFry].length-(256+44)/300) { break" ascii
    $s5  = "function nHpEtZHvLPAUVkTqHaIDBIjNLDzCOXGhmYytSZknZbDdlMFvWNpuxf(JJskWCyqIrnhz,knUcHSgHIYNjTF){ return SKzDt[NDsoJ(JJskWCyqIrnhz[" ascii
    $s6  = "function LkduedouQdclpKtFP(cZjSu){aNMZZQMJJjC= '';HLGPQWKTFry=(-482+482)/285; while(true){if(HLGPQWKTFry >= (483+661)/572)break;" ascii
    $s7  = "function nHpEtZHvLPAUVkTqHaIDBIjNLDzCOXGhmYytSZknZbDdlMFvWNpuxf(JJskWCyqIrnhz,knUcHSgHIYNjTF){ return SKzDt[NDsoJ(JJskWCyqIrnhz[" ascii
    $s8  = "function NDsoJ(lnoIFvqPyOC,jMYlcRotuOjWX,WhFRbITd){aMaA=parseInt(lnoIFvqPyOC,jMYlcRotuOjWX);tGUmZ=aMaA.toString(WhFRbITd);return" ascii
    $s9  = " tGUmZ;}function YoTTFDDogrzedNB(jFaWtfQLYlDFXxHAZ){eval(jFaWtfQLYlDFXxHAZ)}" fullword ascii
    $s10 = "var V=new Array(\"2b\",\"2c\",\"27\",\"2e\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"58\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function HaMpqijfkbt(UCGFOuFd,IryonJ){return UCGFOuFd.split(IryonJ)}" fullword ascii
    $s13 = "var V=new Array(\"2b\",\"2c\",\"27\",\"2e\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s14 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"58\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "++;}HLGPQWKTFry++;} return aNMZZQMJJjC}" fullword ascii
    $s16 = "function NDsoJ(lnoIFvqPyOC,jMYlcRotuOjWX,WhFRbITd){aMaA=parseInt(lnoIFvqPyOC,jMYlcRotuOjWX);tGUmZ=aMaA.toString(WhFRbITd);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}