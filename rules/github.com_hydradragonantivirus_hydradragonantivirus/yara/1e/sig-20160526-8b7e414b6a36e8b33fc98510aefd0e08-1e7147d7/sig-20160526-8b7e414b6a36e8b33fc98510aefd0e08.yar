rule sig_20160526_8b7e414b6a36e8b33fc98510aefd0e08 {
  meta:
    description = "datamaliciousorder - file 20160526_8b7e414b6a36e8b33fc98510aefd0e08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f9fe19de515b3b532ce2104a4d16e6133f8c6e57e9dc7e108a640efb692758c"

  strings:
    $s1  = "function LWzkAxQD(JzPBXxerCpHxI) {var TMXxMX = ORzwvapIQsKLLnUpGz.join(ldIYmLupuHfVcbvdBs[0]);var nLSwCIgsRgbVMvTXNlm, NpiNeAioD" ascii
    $s2  = "os(800), 2) - 1))-771)) vbeFqXBlffEDuBeOUwHvl += tccZRTOUGEePmIvh(nLSwCIgsRgbVMvTXNlm, NpiNeAioDfOamjOf);else vbeFqXBlffEDuBeOUw" ascii
    $s3  = "UwHvl += DO(nLSwCIgsRgbVMvTXNlm);else if (UMPqoLgECSKTgplnYhd == (835 + Math.round((Math.pow(Math.sin(800), 2) + Math.pow(Math.c" ascii
    $s4  = "function wOkrOrrRtWKKVRTgJDONps(fYNKRzSGrMaeHgVc,cuGQxQdhIl){return fYNKRzSGrMaeHgVc.charAt(cuGQxQdhIl);}" fullword ascii
    $s5  = "ngth);return vbeFqXBlffEDuBeOUwHvl;}" fullword ascii
    $s6  = "function DO(kpbQCMZMbHwsYnPfRgwsQkw){return String.fromCharCode(kpbQCMZMbHwsYnPfRgwsQkw);}" fullword ascii
    $s7  = "function LWzkAxQD(JzPBXxerCpHxI) {var TMXxMX = ORzwvapIQsKLLnUpGz.join(ldIYmLupuHfVcbvdBs[0]);var nLSwCIgsRgbVMvTXNlm, NpiNeAioD" ascii
    $s8  = "function CgyiDKIRoBwirFiKgmDI(aRNhgRMeBTwewnvfVQWzhftl,ZWZIfnHMuRfibhkqb,WYpbcWORGCkV){return String.fromCharCode(aRNhgRMeBTwewn" ascii
    $s9  = "function CgyiDKIRoBwirFiKgmDI(aRNhgRMeBTwewnvfVQWzhftl,ZWZIfnHMuRfibhkqb,WYpbcWORGCkV){return String.fromCharCode(aRNhgRMeBTwewn" ascii
    $s10 = "function tccZRTOUGEePmIvh(BbgvS,QDGvqF){return String.fromCharCode(BbgvS,QDGvqF);}" fullword ascii
    $s11 = "function SnNBccCDvtDrMuRbe(bLxdK,REsdTzUeUuUKCWO){return bLxdK.indexOf(REsdTzUeUuUKCWO);}" fullword ascii
    $s12 = "Hvl += CgyiDKIRoBwirFiKgmDI(nLSwCIgsRgbVMvTXNlm, NpiNeAioDfOamjOf, LCjiIGCFoMgTfQpBsxbUb);} while (TikRILQHpq < JzPBXxerCpHxI.le" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}