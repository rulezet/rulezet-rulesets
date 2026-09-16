rule sig_20151211_bc06f0f372870f29cf9977fd046619c2 {
  meta:
    description = "datamaliciousorder - file 20151211_bc06f0f372870f29cf9977fd046619c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1aa9a8e07e4c068982a2e02a5b2eeb6244abebd31f45ec460c5f23de7e9122b6"

  strings:
    $s1  = "function PZmAUfW(wSSlMhGmSHYTjFmCobaMQxbqhtxYDMFqHaot) {return !isNaN(parseFloat(wSSlMhGmSHYTjFmCobaMQxbqhtxYDMFqHaot)) && isFin" ascii
    $s2  = "function PZmAUfW(wSSlMhGmSHYTjFmCobaMQxbqhtxYDMFqHaot) {return !isNaN(parseFloat(wSSlMhGmSHYTjFmCobaMQxbqhtxYDMFqHaot)) && isFin" ascii
    $s3  = ";zScUoiVfX[voFKTBMJIgr]=(-266+266)/774; while(true) { if(zScUoiVfX[voFKTBMJIgr] > IqGpq[voFKTBMJIgr].length-(674+32)/706) { brea" ascii
    $s4  = "function TzKCP(KphITjnxqUy,QJJyRehgLWvie,JULnWSOo){jtMy=parseInt(KphITjnxqUy,QJJyRehgLWvie);jTWYi=jtMy.toString(JULnWSOo);return" ascii
    $s5  = "var U=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function TJVMlQrqTze(JngqTmIq,ZhVkqo){return JngqTmIq.split(ZhVkqo)}" fullword ascii
    $s7  = "var V=new Array(\"29\",\"2a\",\"28\",\"2e\",\"27\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "++;}voFKTBMJIgr++;} return YFVClwFCMAl}" fullword ascii
    $s9  = "var V=new Array(\"29\",\"2a\",\"28\",\"2e\",\"27\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "var U=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function BCRJNGvrmZdLcAamq(IqGpq){YFVClwFCMAl= '';voFKTBMJIgr=(-872+872)/297; while(true){if(voFKTBMJIgr >= (1090+554)/822)break" ascii
    $s12 = "function BCRJNGvrmZdLcAamq(IqGpq){YFVClwFCMAl= '';voFKTBMJIgr=(-872+872)/297; while(true){if(voFKTBMJIgr >= (1090+554)/822)break" ascii
    $s13 = "function AwtBxRtnJULMySOgELPpEAImYNIHqqSGkrHGhNxgcmbvXOPQBdLCWd(nhUsbmxDKCZAn,gyJxvcRkgYgKDh){ return nPCAA[TzKCP(nhUsbmxDKCZAn[" ascii
    $s14 = "function TzKCP(KphITjnxqUy,QJJyRehgLWvie,JULnWSOo){jtMy=parseInt(KphITjnxqUy,QJJyRehgLWvie);jTWYi=jtMy.toString(JULnWSOo);return" ascii
    $s15 = " jTWYi;}function RVhdeECoAOBZhAc(JjplCANOfhHrBtAYL){eval(JjplCANOfhHrBtAYL)}" fullword ascii
    $s16 = "function AwtBxRtnJULMySOgELPpEAImYNIHqqSGkrHGhNxgcmbvXOPQBdLCWd(nhUsbmxDKCZAn,gyJxvcRkgYgKDh){ return nPCAA[TzKCP(nhUsbmxDKCZAn[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}