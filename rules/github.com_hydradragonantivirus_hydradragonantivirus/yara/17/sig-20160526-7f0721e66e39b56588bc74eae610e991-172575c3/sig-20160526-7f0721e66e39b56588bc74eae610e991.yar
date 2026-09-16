rule sig_20160526_7f0721e66e39b56588bc74eae610e991 {
  meta:
    description = "datamaliciousorder - file 20160526_7f0721e66e39b56588bc74eae610e991.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74daecc1ab8d5e25ffdcf37f9958680de170520a8ce72d772d7408dd5c80f943"

  strings:
    $s1  = "function qNfVmSq(FTXLXCKrcIHIj) {var XGSKz = CnVlspcOHYv.join(QnHFIqBpO[0]);var TRFPQBwRTsNQwh, GkoqnSVuZ, yefdLGGXwS, YdbrquRJE" ascii
    $s2  = "), 2) + Math.pow(Math.cos(533), 2) - 1))-847)) VSgFUmkTdLdI += wP(TRFPQBwRTsNQwh);else if (GeLylJsORPQ == (298 + Math.round((Mat" ascii
    $s3  = "(442), 2) + Math.pow(Math.cos(442), 2) - 1))-941) | ohXBADoSwGqa<< (605 + Math.round((Math.pow(Math.sin(212), 2) + Math.pow(Math" ascii
    $s4  = "function cBQEiCMppqs(ykDMt,MDfrxVJStOQkwgL){return ykDMt.charAt(MDfrxVJStOQkwgL);}" fullword ascii
    $s5  = "lse VSgFUmkTdLdI += kyncfAMI(TRFPQBwRTsNQwh, GkoqnSVuZ, yefdLGGXwS);} while (SQJTjo < FTXLXCKrcIHIj.length);return VSgFUmkTdLdI;" ascii
    $s6  = "function rdAnmDrwThxTzrtklm(FmxqkPxJhhMmEzAl,uNIQaTOme){return String.fromCharCode(FmxqkPxJhhMmEzAl,uNIQaTOme);}" fullword ascii
    $s7  = "function kyncfAMI(GOGQPkEWeVqe,xwSHr,AipKaVVirhZYGEfhaGbcoyt){return String.fromCharCode(GOGQPkEWeVqe,xwSHr,AipKaVVirhZYGEfhaGbc" ascii
    $s8  = "function wP(GOUESLxKXOcByBnAkAehIKb){return String.fromCharCode(GOUESLxKXOcByBnAkAehIKb);}" fullword ascii
    $s9  = "function kyncfAMI(GOGQPkEWeVqe,xwSHr,AipKaVVirhZYGEfhaGbcoyt){return String.fromCharCode(GOGQPkEWeVqe,xwSHr,AipKaVVirhZYGEfhaGbc" ascii
    $s10 = "function dJTGuPxtAGwoeEkmBdoiYIF(ZPbSTqYNQq,jJpwf){return ZPbSTqYNQq.indexOf(jJpwf);}" fullword ascii
    $s11 = "function qNfVmSq(FTXLXCKrcIHIj) {var XGSKz = CnVlspcOHYv.join(QnHFIqBpO[0]);var TRFPQBwRTsNQwh, GkoqnSVuZ, yefdLGGXwS, YdbrquRJE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}