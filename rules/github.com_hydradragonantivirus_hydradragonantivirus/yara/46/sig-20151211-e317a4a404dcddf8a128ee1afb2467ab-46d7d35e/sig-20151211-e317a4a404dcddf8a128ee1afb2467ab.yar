rule sig_20151211_e317a4a404dcddf8a128ee1afb2467ab {
  meta:
    description = "datamaliciousorder - file 20151211_e317a4a404dcddf8a128ee1afb2467ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0639d13fbea6c91c8c9f162f8947588462064a75a8ab0a3fabf511859be304f2"

  strings:
    $s1  = "function xFFahaa(godruLhXXBoHXAFrktQxOyVAZFflSbvoaflk) {return !isNaN(parseFloat(godruLhXXBoHXAFrktQxOyVAZFflSbvoaflk)) && isFin" ascii
    $s2  = "function xFFahaa(godruLhXXBoHXAFrktQxOyVAZFflSbvoaflk) {return !isNaN(parseFloat(godruLhXXBoHXAFrktQxOyVAZFflSbvoaflk)) && isFin" ascii
    $s3  = "function uncez(UqxRViENwUT,jeANmdhAUonjb,YoSeghor){BICW=parseInt(UqxRViENwUT,jeANmdhAUonjb);asqss=BICW.toString(YoSeghor);return" ascii
    $s4  = "function bwnDgEwqlehXQODJY(druhz){fIHwAxsZzyo= '';MUuVkMKIcXD=(-908+908)/127; while(true){if(MUuVkMKIcXD >= (396+704)/550)break;" ascii
    $s5  = "function bwnDgEwqlehXQODJY(druhz){fIHwAxsZzyo= '';MUuVkMKIcXD=(-908+908)/127; while(true){if(MUuVkMKIcXD >= (396+704)/550)break;" ascii
    $s6  = " asqss;}function oxoVLEWmBWOUVbt(FysvnQUMQcSEGgXVn){eval(FysvnQUMQcSEGgXVn)}" fullword ascii
    $s7  = "nSNWxKHlo[MUuVkMKIcXD]=(-73+73)/588; while(true) { if(nSNWxKHlo[MUuVkMKIcXD] > druhz[MUuVkMKIcXD].length-(-86+132)/46) { break; " ascii
    $s8  = ";}MUuVkMKIcXD++;} return fIHwAxsZzyo}" fullword ascii
    $s9  = "function xlCBCryYjWcLjPqfzcbsFnWbMqPkZdaltpqQAVeYrfSkBgTSqTgFzN(VjXNozzLQljgQ,sXaDzbXgGNGuOL){ return zzctf[uncez(VjXNozzLQljgQ[" ascii
    $s10 = "var b=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"40\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var P=new Array(\"2f\",\"2c\",\"29\",\"2b\",\"2f\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = "function xlCBCryYjWcLjPqfzcbsFnWbMqPkZdaltpqQAVeYrfSkBgTSqTgFzN(VjXNozzLQljgQ,sXaDzbXgGNGuOL){ return zzctf[uncez(VjXNozzLQljgQ[" ascii
    $s13 = "var b=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"40\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "var P=new Array(\"2f\",\"2c\",\"29\",\"2b\",\"2f\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s15 = "function xduaPcMUegJ(eAKElcEP,DGVaPo){return eAKElcEP.split(DGVaPo)}" fullword ascii
    $s16 = "function uncez(UqxRViENwUT,jeANmdhAUonjb,YoSeghor){BICW=parseInt(UqxRViENwUT,jeANmdhAUonjb);asqss=BICW.toString(YoSeghor);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}