rule sig_20151211_ee15a064cdaff68e93d8d079fc267202 {
  meta:
    description = "datamaliciousorder - file 20151211_ee15a064cdaff68e93d8d079fc267202.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32d8f089083d273db1d35ce7e6685e2b941bd9f5b6e718c856c66686b461506c"

  strings:
    $s1  = "function TfFKdgd(gVuqwUpRsEKJmzCDFmhDIeteqEWAJKMFthtg) {return !isNaN(parseFloat(gVuqwUpRsEKJmzCDFmhDIeteqEWAJKMFthtg)) && isFin" ascii
    $s2  = "function TfFKdgd(gVuqwUpRsEKJmzCDFmhDIeteqEWAJKMFthtg) {return !isNaN(parseFloat(gVuqwUpRsEKJmzCDFmhDIeteqEWAJKMFthtg)) && isFin" ascii
    $s3  = "function BXpXVCRQdaTlgAnPA(hiqMy){rSyWjCYGJdV= '';cEoPRNZwUzp=(-475+475)/862; while(true){if(cEoPRNZwUzp >= (1216+548)/882)break" ascii
    $s4  = "function BXpXVCRQdaTlgAnPA(hiqMy){rSyWjCYGJdV= '';cEoPRNZwUzp=(-475+475)/862; while(true){if(cEoPRNZwUzp >= (1216+548)/882)break" ascii
    $s5  = "function hHvijqzYAhgOuNIFqmQLVPNXRxYMEkhZUmeqdOdzuVFUHlYUcxpNpK(MvfLYnOsUrVGj,rPGNywjwthrEof){ return SLgpW[sbyJK(MvfLYnOsUrVGj[" ascii
    $s6  = " FVnkZ;}function zUlcebgPYLgZPaf(TDixxlDKYnakHfIpQ){eval(TDixxlDKYnakHfIpQ)}" fullword ascii
    $s7  = "]++;}cEoPRNZwUzp++;} return rSyWjCYGJdV}" fullword ascii
    $s8  = "var i=new Array(\"2d\",\"29\",\"2d\",\"2c\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s9  = "function hHvijqzYAhgOuNIFqmQLVPNXRxYMEkhZUmeqdOdzuVFUHlYUcxpNpK(MvfLYnOsUrVGj,rPGNywjwthrEof){ return SLgpW[sbyJK(MvfLYnOsUrVGj[" ascii
    $s10 = "function GJqVRZbDOaa(KMlYiOyB,ReZEAz){return KMlYiOyB.split(ReZEAz)}" fullword ascii
    $s11 = "function sbyJK(deBRDpIxzXk,goqfOjbDKAShF,ZBkweVfM){sEqd=parseInt(deBRDpIxzXk,goqfOjbDKAShF);FVnkZ=sEqd.toString(ZBkweVfM);return" ascii
    $s12 = "var A=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = ";dbftnqipL[cEoPRNZwUzp]=(-278+278)/948; while(true) { if(dbftnqipL[cEoPRNZwUzp] > hiqMy[cEoPRNZwUzp].length-(289+379)/668) { bre" ascii
    $s14 = "function sbyJK(deBRDpIxzXk,goqfOjbDKAShF,ZBkweVfM){sEqd=parseInt(deBRDpIxzXk,goqfOjbDKAShF);FVnkZ=sEqd.toString(ZBkweVfM);return" ascii
    $s15 = "var A=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5g\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "var i=new Array(\"2d\",\"29\",\"2d\",\"2c\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}