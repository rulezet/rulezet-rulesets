rule sig_20160526_4f76d90e696eb8dcea51e1a9bfa9d8c9 {
  meta:
    description = "datamaliciousorder - file 20160526_4f76d90e696eb8dcea51e1a9bfa9d8c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d698a31bb41527dee6ce38470d32df928247a421a44007d3cd73dc2fc9a79b9e"

  strings:
    $s1  = "aKPDeVELSlNdlnw);else if (nPCGtxgmhqpa == (476 + Math.round((Math.pow(Math.sin(900), 2) + Math.pow(Math.cos(900), 2) - 1))-412))" ascii
    $s2  = "ound((Math.pow(Math.sin(678), 2) + Math.pow(Math.cos(678), 2) - 1))-729) | MxcslAghWAHaPYtSt<< (414 + Math.round((Math.pow(Math." ascii
    $s3  = "function PfkGoRBlo(PbuytswlHOEIR) {var WqoFbMbeVVWLZJIlEl = KJhJixHnX.join(oKewPSJAbWGOT[0]);var LCAaKPDeVELSlNdlnw, GcXdnmbKScX" ascii
    $s4  = "function IThsmiCgJTRCRqzrMAA(qGXBWNSKAFpXWPoj,bDeBKPxTciZc){return qGXBWNSKAFpXWPoj.charAt(bDeBKPxTciZc);}" fullword ascii
    $s5  = "function K(FnMTuXdwCJoYRGgzlAPKT){return String.fromCharCode(FnMTuXdwCJoYRGgzlAPKT);}" fullword ascii
    $s6  = "function iLQLcSyGAlsqlPMj(tetydoBXWbH,YSyWhwwKPKaJeSvvdWjE,xuZDqUmqWtaLjLulfmgh){return String.fromCharCode(tetydoBXWbH,YSyWhwwK" ascii
    $s7  = "function iLQLcSyGAlsqlPMj(tetydoBXWbH,YSyWhwwKPKaJeSvvdWjE,xuZDqUmqWtaLjLulfmgh){return String.fromCharCode(tetydoBXWbH,YSyWhwwK" ascii
    $s8  = "function JMXRNGiLpghZYChKvlQB(nXfXPZWBTgCfq,ITknCQlOmidfrKdfeuUY){return nXfXPZWBTgCfq.indexOf(ITknCQlOmidfrKdfeuUY);}" fullword ascii
    $s9  = "PDeVELSlNdlnw, GcXdnmbKScXyNrYjlCojkg, clZpnCbpLKOBSMdHT);} while (vEyjfAKTcmymBmrR < PbuytswlHOEIR.length);return yKYhByzsHSXBi" ascii
    $s10 = "function JhfLDKBNmqr(cnTeTymVICnlCBAfsH,aFhPRqtTLIclwPYHR){return String.fromCharCode(cnTeTymVICnlCBAfsH,aFhPRqtTLIclwPYHR);}" fullword ascii
    $s11 = "function PfkGoRBlo(PbuytswlHOEIR) {var WqoFbMbeVVWLZJIlEl = KJhJixHnX.join(oKewPSJAbWGOT[0]);var LCAaKPDeVELSlNdlnw, GcXdnmbKScX" ascii
    $s12 = " yKYhByzsHSXBivaGNJ += JhfLDKBNmqr(LCAaKPDeVELSlNdlnw, GcXdnmbKScXyNrYjlCojkg);else yKYhByzsHSXBivaGNJ += iLQLcSyGAlsqlPMj(LCAaK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}