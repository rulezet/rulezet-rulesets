rule sig_20160526_b9dc32227957364005ff62355a1ecf22 {
  meta:
    description = "datamaliciousorder - file 20160526_b9dc32227957364005ff62355a1ecf22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86e33d12ef92d761c1b55fc5e63a921e9c9f19223f3650ba725742faa5c24d66"

  strings:
    $s1  = "function vnPGmEwsdRLRU(jCqTUlHjZAAZQ) {var zMCXL = wPtXNSOdYq.join(KQXWjwVAgLBB[0]);var NlVgTFBnKgIlvUJmhLVDIyS, rUjBsUuHlPCNDDw" ascii
    $s2  = ") - 1))-274)) saCZqXxxTrjomTmHXv += eYKvtIkCugDnuqXOwbaADr(NlVgTFBnKgIlvUJmhLVDIyS, rUjBsUuHlPCNDDwA);else saCZqXxxTrjomTmHXv +=" ascii
    $s3  = "VgTFBnKgIlvUJmhLVDIyS);else if (ffiKJdZTRMtEFKKiSGp == (338 + Math.round((Math.pow(Math.sin(418), 2) + Math.pow(Math.cos(418), 2" ascii
    $s4  = "function ClvGSCMuAzGWtzeI(pjhwUCIECuu,guxLttPoFXQrPsfy){return pjhwUCIECuu.charAt(guxLttPoFXQrPsfy);}" fullword ascii
    $s5  = "function wD(hzMCRaFESzDKnbR){return String.fromCharCode(hzMCRaFESzDKnbR);}" fullword ascii
    $s6  = "function HDpnxkOBhIBJsdnShBb(dgWSvmyzZm,CPAtTVTtKIusZYXcL,YXVcJehNbWpfeq){return String.fromCharCode(dgWSvmyzZm,CPAtTVTtKIusZYXc" ascii
    $s7  = "function eYKvtIkCugDnuqXOwbaADr(VuPMQcnOgxmrT,gLhwXAEzo){return String.fromCharCode(VuPMQcnOgxmrT,gLhwXAEzo);}" fullword ascii
    $s8  = "function HDpnxkOBhIBJsdnShBb(dgWSvmyzZm,CPAtTVTtKIusZYXcL,YXVcJehNbWpfeq){return String.fromCharCode(dgWSvmyzZm,CPAtTVTtKIusZYXc" ascii
    $s9  = "function vnPGmEwsdRLRU(jCqTUlHjZAAZQ) {var zMCXL = wPtXNSOdYq.join(KQXWjwVAgLBB[0]);var NlVgTFBnKgIlvUJmhLVDIyS, rUjBsUuHlPCNDDw" ascii
    $s10 = "function ovAVA(nnjUIpcnHBF,OHtkTJNofg){return nnjUIpcnHBF.indexOf(OHtkTJNofg);}" fullword ascii
    $s11 = " HDpnxkOBhIBJsdnShBb(NlVgTFBnKgIlvUJmhLVDIyS, rUjBsUuHlPCNDDwA, GekjQyHQBGKE);} while (vWSATgTY < jCqTUlHjZAAZQ.length);return s" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}