rule sig_20160525_a3687a44563481d2f05c0917a23b121d {
  meta:
    description = "datamaliciousorder - file 20160525_a3687a44563481d2f05c0917a23b121d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76042570844b422ed04edf556dd74d95fec368f9a896e08f5db80905ecae41ec"

  strings:
    $s1  = ") - 1))-619)) izzohGrvfJNLb += CO(pTDePksdJvjJtn);else if (yICJrMZnJkB == (315 + Math.round((Math.pow(Math.sin(457), 2) + Math.p" ascii
    $s2  = "function XtXUZ(VTogeKHVntyPV) {var zHhRRkwm = QwftL.join(XhZCnvokcskgAtSxDf[0]);var pTDePksdJvjJtn, zRnLujTYxKlZUBGqjAi, JkiWEiY" ascii
    $s3  = "ow(Math.cos(457), 2) - 1))-251)) izzohGrvfJNLb += mzzeZ(pTDePksdJvjJtn, zRnLujTYxKlZUBGqjAi);else izzohGrvfJNLb += yLbwPRQDWcKHj" ascii
    $s4  = "function fOxkCWWuixMnSxIexSwAo(keIOzCvudPOVzm,fiWfjyyMfmqjlnBV){return keIOzCvudPOVzm.charAt(fiWfjyyMfmqjlnBV);}" fullword ascii
    $s5  = "Cqbl(pTDePksdJvjJtn, zRnLujTYxKlZUBGqjAi, JkiWEiYRxfKAw);} while (AxjdD < VTogeKHVntyPV.length);return izzohGrvfJNLb;}" fullword ascii
    $s6  = "function XtXUZ(VTogeKHVntyPV) {var zHhRRkwm = QwftL.join(XhZCnvokcskgAtSxDf[0]);var pTDePksdJvjJtn, zRnLujTYxKlZUBGqjAi, JkiWEiY" ascii
    $s7  = "function PtTjbSmBYmCCqHnWjNIWUu(CemOIDatEITQdFQksJCiR,bwoIfrMyjsEUTapsUE){return CemOIDatEITQdFQksJCiR.indexOf(bwoIfrMyjsEUTapsU" ascii
    $s8  = "function yLbwPRQDWcKHjCqbl(ioapuHlIgNYxDLFHb,KqapJIwyrzdpFh,NtsQseyFOhwxAyFsgRGksUwA){return String.fromCharCode(ioapuHlIgNYxDLF" ascii
    $s9  = "function PtTjbSmBYmCCqHnWjNIWUu(CemOIDatEITQdFQksJCiR,bwoIfrMyjsEUTapsUE){return CemOIDatEITQdFQksJCiR.indexOf(bwoIfrMyjsEUTapsU" ascii
    $s10 = "function mzzeZ(PTXBNRFktpZukl,VAWakQytNfjo){return String.fromCharCode(PTXBNRFktpZukl,VAWakQytNfjo);}" fullword ascii
    $s11 = "function CO(hFEEXALIh){return String.fromCharCode(hFEEXALIh);}" fullword ascii
    $s12 = "function yLbwPRQDWcKHjCqbl(ioapuHlIgNYxDLFHb,KqapJIwyrzdpFh,NtsQseyFOhwxAyFsgRGksUwA){return String.fromCharCode(ioapuHlIgNYxDLF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}