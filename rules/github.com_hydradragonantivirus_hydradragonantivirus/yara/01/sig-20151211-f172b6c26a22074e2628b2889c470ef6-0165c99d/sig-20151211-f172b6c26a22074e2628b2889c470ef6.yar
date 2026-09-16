rule sig_20151211_f172b6c26a22074e2628b2889c470ef6 {
  meta:
    description = "datamaliciousorder - file 20151211_f172b6c26a22074e2628b2889c470ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ef02a4570e99e17ee4e59ea57e4fb52413db6d6d66ff270b47e6186a545d943"

  strings:
    $s1  = "function MPFFJYI(hQNKgVznmTvtCKtJIkPMjDpMcvJEZBtqJdDz) {return !isNaN(parseFloat(hQNKgVznmTvtCKtJIkPMjDpMcvJEZBtqJdDz)) && isFin" ascii
    $s2  = "function MPFFJYI(hQNKgVznmTvtCKtJIkPMjDpMcvJEZBtqJdDz) {return !isNaN(parseFloat(hQNKgVznmTvtCKtJIkPMjDpMcvJEZBtqJdDz)) && isFin" ascii
    $s3  = "var I=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "var O=new Array(\"2d\",\"2d\",\"26\",\"2f\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "function tVvcqBafGYl(rGVskpoh,NMAZGk){return rGVskpoh.split(NMAZGk)}" fullword ascii
    $s6  = "function ZpYlK(nJvfqseTrIo,dtJFbhGNudmjc,wxCBHkeP){VnaR=parseInt(nJvfqseTrIo,dtJFbhGNudmjc);ZBSlg=VnaR.toString(wxCBHkeP);return" ascii
    $s7  = "function aZPkmRBLFBFplvAXmYpJWBjNXrHvioTGbnEbJLiTYVCRWVbTVdKZsc(lMSjcbIkyXWZh,AIfZmQdgxnotJF){ return fhDPD[ZpYlK(lMSjcbIkyXWZh[" ascii
    $s8  = "var I=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "function atNsLjNLjxBfQYOaa(GEVEU){gVltqQHPLXS= '';CHHWXkpIPxz=(-889+889)/449; while(true){if(CHHWXkpIPxz >= (1004+146)/575)break" ascii
    $s10 = "function ZpYlK(nJvfqseTrIo,dtJFbhGNudmjc,wxCBHkeP){VnaR=parseInt(nJvfqseTrIo,dtJFbhGNudmjc);ZBSlg=VnaR.toString(wxCBHkeP);return" ascii
    $s11 = "]++;}CHHWXkpIPxz++;} return gVltqQHPLXS}" fullword ascii
    $s12 = " ZBSlg;}function QpEoimSArggRIus(pPEDGGJlgBZDVWeuO){eval(pPEDGGJlgBZDVWeuO)}" fullword ascii
    $s13 = ";ebkjeiFqJ[CHHWXkpIPxz]=(-653+653)/601; while(true) { if(ebkjeiFqJ[CHHWXkpIPxz] > GEVEU[CHHWXkpIPxz].length-(459+348)/807) { bre" ascii
    $s14 = "var O=new Array(\"2d\",\"2d\",\"26\",\"2f\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s15 = "function atNsLjNLjxBfQYOaa(GEVEU){gVltqQHPLXS= '';CHHWXkpIPxz=(-889+889)/449; while(true){if(CHHWXkpIPxz >= (1004+146)/575)break" ascii
    $s16 = "function aZPkmRBLFBFplvAXmYpJWBjNXrHvioTGbnEbJLiTYVCRWVbTVdKZsc(lMSjcbIkyXWZh,AIfZmQdgxnotJF){ return fhDPD[ZpYlK(lMSjcbIkyXWZh[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}