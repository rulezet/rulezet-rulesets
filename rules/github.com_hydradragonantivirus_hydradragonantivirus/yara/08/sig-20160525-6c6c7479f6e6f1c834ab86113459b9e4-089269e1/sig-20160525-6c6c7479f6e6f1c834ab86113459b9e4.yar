rule sig_20160525_6c6c7479f6e6f1c834ab86113459b9e4 {
  meta:
    description = "datamaliciousorder - file 20160525_6c6c7479f6e6f1c834ab86113459b9e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd23a9f1fa918992893a39d64025cfe7191a9ce448ce355d3485ddaa93b07447"

  strings:
    $s1  = "ath.cos(366), 2) - 1))-242)) iCxdLftznoLvLKJYRVjG += jhIFmEV(WkBjlNnzzZI, kCpdNnHDMVliuUICeaUozXb);else iCxdLftznoLvLKJYRVjG += " ascii
    $s2  = ") | zDifTFxTwiAX<< (148 + Math.round((Math.pow(Math.sin(300), 2) + Math.pow(Math.cos(300), 2) - 1))-136) | HgXEFmO<< (210 + Math" ascii
    $s3  = "function HAhePhV(vLYcGzyGOJSGd) {var vAwXazEMUkjSkCoqnjOyegi = VZdQHCARH.join(DLWvBjhwakuWsqjs[0]);var WkBjlNnzzZI, kCpdNnHDMVli" ascii
    $s4  = "5)) iCxdLftznoLvLKJYRVjG += Kz(WkBjlNnzzZI);else if (LMsXUEAvBvwKQ == (306 + Math.round((Math.pow(Math.sin(366), 2) + Math.pow(M" ascii
    $s5  = "function bbWwEI(EOnmNsDRdNPZnYfdOCJ,CpxpJFqekaJdmYkbZYXcpc){return EOnmNsDRdNPZnYfdOCJ.charAt(CpxpJFqekaJdmYkbZYXcpc);}" fullword ascii
    $s6  = "function sSwEtKwMyFLMJ(piKoRcS,DoqiF){return piKoRcS.indexOf(DoqiF);}" fullword ascii
    $s7  = "zgJmsjxtrVtEjEUne(WkBjlNnzzZI, kCpdNnHDMVliuUICeaUozXb, HwMdSNiywWsPSHhcGed);} while (MrzPibkE < vLYcGzyGOJSGd.length);return iC" ascii
    $s8  = "function jhIFmEV(VGLIugOZ,SUJJvuvdytUzCQEVeJ){return String.fromCharCode(VGLIugOZ,SUJJvuvdytUzCQEVeJ);}" fullword ascii
    $s9  = "function zgJmsjxtrVtEjEUne(iKjvPfs,CdQGYscGBKlMLnu,PqJpSbQYnIXdTsvbUYMiXrB){return String.fromCharCode(iKjvPfs,CdQGYscGBKlMLnu,P" ascii
    $s10 = "function zgJmsjxtrVtEjEUne(iKjvPfs,CdQGYscGBKlMLnu,PqJpSbQYnIXdTsvbUYMiXrB){return String.fromCharCode(iKjvPfs,CdQGYscGBKlMLnu,P" ascii
    $s11 = "function Kz(EwrdyyxRZUuhcHatoet){return String.fromCharCode(EwrdyyxRZUuhcHatoet);}" fullword ascii
    $s12 = "function HAhePhV(vLYcGzyGOJSGd) {var vAwXazEMUkjSkCoqnjOyegi = VZdQHCARH.join(DLWvBjhwakuWsqjs[0]);var WkBjlNnzzZI, kCpdNnHDMVli" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}