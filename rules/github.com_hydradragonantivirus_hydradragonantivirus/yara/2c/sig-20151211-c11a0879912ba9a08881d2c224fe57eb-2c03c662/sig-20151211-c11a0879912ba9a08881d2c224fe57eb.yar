rule sig_20151211_c11a0879912ba9a08881d2c224fe57eb {
  meta:
    description = "datamaliciousorder - file 20151211_c11a0879912ba9a08881d2c224fe57eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cd546b6a18d124715e49b25099006d6a6aee9f1eee0b6b856a05ce7c5f1cc36"

  strings:
    $s1  = "function pmXCXbp(hOnkiAELhJMxICgDxXzpaUKHtLZYJDmbyEgy) {return !isNaN(parseFloat(hOnkiAELhJMxICgDxXzpaUKHtLZYJDmbyEgy)) && isFin" ascii
    $s2  = "function pmXCXbp(hOnkiAELhJMxICgDxXzpaUKHtLZYJDmbyEgy) {return !isNaN(parseFloat(hOnkiAELhJMxICgDxXzpaUKHtLZYJDmbyEgy)) && isFin" ascii
    $s3  = "function fSaKJVhRQUUuIQGYuxeZozXpXvNugsurRLdzjzqlpfHbSYBnjzHreK(LxBkfdKHslAwV,dAtYzqBKQNoRTO){ return VsJKb[UBSXc(LxBkfdKHslAwV[" ascii
    $s4  = "++;}FHvWobbcqxX++;} return jLuSFxukiKG}" fullword ascii
    $s5  = "function okrQjtxRshgbCzRfB(NxgjD){jLuSFxukiKG= '';FHvWobbcqxX=(-824+824)/728; while(true){if(FHvWobbcqxX >= (666+708)/687)break;" ascii
    $s6  = "var C=new Array(\"2a\",\"2d\",\"2d\",\"2a\",\"2b\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s7  = "function WnWWPhuIUza(rAzmvuVH,tWdEoP){return rAzmvuVH.split(tWdEoP)}" fullword ascii
    $s8  = "var W=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"45\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "vNUCJwaUP[FHvWobbcqxX]=(-984+984)/917; while(true) { if(vNUCJwaUP[FHvWobbcqxX] > NxgjD[FHvWobbcqxX].length-(322+284)/606) { brea" ascii
    $s10 = "function okrQjtxRshgbCzRfB(NxgjD){jLuSFxukiKG= '';FHvWobbcqxX=(-824+824)/728; while(true){if(FHvWobbcqxX >= (666+708)/687)break;" ascii
    $s11 = "var C=new Array(\"2a\",\"2d\",\"2d\",\"2a\",\"2b\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = "var W=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"45\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "function fSaKJVhRQUUuIQGYuxeZozXpXvNugsurRLdzjzqlpfHbSYBnjzHreK(LxBkfdKHslAwV,dAtYzqBKQNoRTO){ return VsJKb[UBSXc(LxBkfdKHslAwV[" ascii
    $s14 = " lwyYB;}function sNoYVwPzrCPJxxc(ErFcDxYyAIMGBedNO){eval(ErFcDxYyAIMGBedNO)}" fullword ascii
    $s15 = "function UBSXc(QRKLyaLjVfn,aZhgcMQLixUcX,njLnanvh){ncwF=parseInt(QRKLyaLjVfn,aZhgcMQLixUcX);lwyYB=ncwF.toString(njLnanvh);return" ascii
    $s16 = "function UBSXc(QRKLyaLjVfn,aZhgcMQLixUcX,njLnanvh){ncwF=parseInt(QRKLyaLjVfn,aZhgcMQLixUcX);lwyYB=ncwF.toString(njLnanvh);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}