rule sig_20151211_a8fc26686136be052ae73fba83838ce9 {
  meta:
    description = "datamaliciousorder - file 20151211_a8fc26686136be052ae73fba83838ce9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73680f97c14c81cacef2a041ba5fa812222caf2b38cfc7bdd3b5fff943d7a57b"

  strings:
    $s1  = "function chWZQzR(mKWwkxzKzNEXapOIZalekqPHrZEUbQEwkVqu) {return !isNaN(parseFloat(mKWwkxzKzNEXapOIZalekqPHrZEUbQEwkVqu)) && isFin" ascii
    $s2  = "function chWZQzR(mKWwkxzKzNEXapOIZalekqPHrZEUbQEwkVqu) {return !isNaN(parseFloat(mKWwkxzKzNEXapOIZalekqPHrZEUbQEwkVqu)) && isFin" ascii
    $s3  = "function TbzjIJgoPaWSEoKiTDNFmeuohdOEYBXkeGwgHaDVItyhvUQTPDNBQD(EEfQuSRGylQeD,TBshIJzcHqkxUe){ return wVQvT[nujeo(EEfQuSRGylQeD[" ascii
    $s4  = "function nujeo(UutQiOKcQPe,LJNjBuFVaAXAB,AdnqjbKt){yEQV=parseInt(UutQiOKcQPe,LJNjBuFVaAXAB);grOyz=yEQV.toString(AdnqjbKt);return" ascii
    $s5  = "rnaAiNnbt[yIUOSXYBzVX]=(-207+207)/463; while(true) { if(rnaAiNnbt[yIUOSXYBzVX] > cyPCd[yIUOSXYBzVX].length-(111+489)/600) { brea" ascii
    $s6  = "var G=new Array(\"2e\",\"27\",\"2d\",\"2c\",\"2c\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s7  = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "function KfRmlswlfBZhonzap(cyPCd){kENJqUjRKXj= '';yIUOSXYBzVX=(-263+263)/592; while(true){if(yIUOSXYBzVX >= (695+549)/622)break;" ascii
    $s9  = "var G=new Array(\"2e\",\"27\",\"2d\",\"2c\",\"2c\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "function TbzjIJgoPaWSEoKiTDNFmeuohdOEYBXkeGwgHaDVItyhvUQTPDNBQD(EEfQuSRGylQeD,TBshIJzcHqkxUe){ return wVQvT[nujeo(EEfQuSRGylQeD[" ascii
    $s11 = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function KfRmlswlfBZhonzap(cyPCd){kENJqUjRKXj= '';yIUOSXYBzVX=(-263+263)/592; while(true){if(yIUOSXYBzVX >= (695+549)/622)break;" ascii
    $s13 = "+;}yIUOSXYBzVX++;} return kENJqUjRKXj}" fullword ascii
    $s14 = " grOyz;}function QduJfPawWkQneVt(kRnvQCufWZcRAbSuH){eval(kRnvQCufWZcRAbSuH)}" fullword ascii
    $s15 = "function nujeo(UutQiOKcQPe,LJNjBuFVaAXAB,AdnqjbKt){yEQV=parseInt(UutQiOKcQPe,LJNjBuFVaAXAB);grOyz=yEQV.toString(AdnqjbKt);return" ascii
    $s16 = "function XUdwYEcIndr(BGoghiaz,MDdpmn){return BGoghiaz.split(MDdpmn)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}