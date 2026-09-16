rule sig_20151211_b8ec23415125bb09ae3e973a4fcd81af {
  meta:
    description = "datamaliciousorder - file 20151211_b8ec23415125bb09ae3e973a4fcd81af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72d688d507c50668c15eddaadff0b74f5ea0016dd4d6efdaf3e0fb7f66ae41ed"

  strings:
    $s1  = "function PMLgxoO(EIwyAWJavbgUyBOqvOdJStYuXFFnyQOfeYEP) {return !isNaN(parseFloat(EIwyAWJavbgUyBOqvOdJStYuXFFnyQOfeYEP)) && isFin" ascii
    $s2  = "function PMLgxoO(EIwyAWJavbgUyBOqvOdJStYuXFFnyQOfeYEP) {return !isNaN(parseFloat(EIwyAWJavbgUyBOqvOdJStYuXFFnyQOfeYEP)) && isFin" ascii
    $s3  = " PEUFG;}function HfLmlRiwWwwPphL(UDIYiMBOqrfynFzeH){eval(UDIYiMBOqrfynFzeH)}" fullword ascii
    $s4  = "var A=new Array(\"2e\",\"27\",\"28\",\"2d\",\"2e\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "var A=new Array(\"2e\",\"27\",\"28\",\"2d\",\"2e\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = "function nmmGsLqCHPsGgMUXU(gnafh){QpmFqVNiyst= '';psbPLEwRdpj=(-833+833)/133; while(true){if(psbPLEwRdpj >= (-118+146)/14)break;" ascii
    $s7  = "j]++;}psbPLEwRdpj++;} return QpmFqVNiyst}" fullword ascii
    $s8  = "XgdxMYoOp[psbPLEwRdpj]=(-308+308)/182; while(true) { if(XgdxMYoOp[psbPLEwRdpj] > gnafh[psbPLEwRdpj].length-(-461+912)/451) { bre" ascii
    $s9  = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"35\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "var a=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"35\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function KzajFUYEhfLZswrigDkgOTmYawsmuBQbroxAHOgkVeoBpFcCKtFnzC(BmCVuQquMNjzt,YFAXGYDREzSeOF){ return lmzPM[rBzjc(BmCVuQquMNjzt[" ascii
    $s12 = "function rBzjc(LjfpZiBeYkd,FSoKoPTGHCLle,hnvIYUNp){XXet=parseInt(LjfpZiBeYkd,FSoKoPTGHCLle);PEUFG=XXet.toString(hnvIYUNp);return" ascii
    $s13 = "function rBzjc(LjfpZiBeYkd,FSoKoPTGHCLle,hnvIYUNp){XXet=parseInt(LjfpZiBeYkd,FSoKoPTGHCLle);PEUFG=XXet.toString(hnvIYUNp);return" ascii
    $s14 = "function fkuYSxwoXkg(tIXdugRp,HHMFOC){return tIXdugRp.split(HHMFOC)}" fullword ascii
    $s15 = "function nmmGsLqCHPsGgMUXU(gnafh){QpmFqVNiyst= '';psbPLEwRdpj=(-833+833)/133; while(true){if(psbPLEwRdpj >= (-118+146)/14)break;" ascii
    $s16 = "function KzajFUYEhfLZswrigDkgOTmYawsmuBQbroxAHOgkVeoBpFcCKtFnzC(BmCVuQquMNjzt,YFAXGYDREzSeOF){ return lmzPM[rBzjc(BmCVuQquMNjzt[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}