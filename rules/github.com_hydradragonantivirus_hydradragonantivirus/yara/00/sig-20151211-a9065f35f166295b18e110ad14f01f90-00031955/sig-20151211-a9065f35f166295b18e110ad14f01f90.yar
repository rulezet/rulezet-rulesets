rule sig_20151211_a9065f35f166295b18e110ad14f01f90 {
  meta:
    description = "datamaliciousorder - file 20151211_a9065f35f166295b18e110ad14f01f90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45f80de00f30767bb5fec5edff425e49012ffd3747af6fe0f61c27f4dbdb68d9"

  strings:
    $s1  = "function HkzPRGt(kVtXrWzdqokjIPJzsXVsbdnoSnMrGgOCpSRH) {return !isNaN(parseFloat(kVtXrWzdqokjIPJzsXVsbdnoSnMrGgOCpSRH)) && isFin" ascii
    $s2  = "function HkzPRGt(kVtXrWzdqokjIPJzsXVsbdnoSnMrGgOCpSRH) {return !isNaN(parseFloat(kVtXrWzdqokjIPJzsXVsbdnoSnMrGgOCpSRH)) && isFin" ascii
    $s3  = "function KytvqvPEEDH(UipBlLOq,pOJocJ){return UipBlLOq.split(pOJocJ)}" fullword ascii
    $s4  = " EglMJ;}function xopdMwukOBNsVSf(LDgiNVzrJxOkTYTJF){eval(LDgiNVzrJxOkTYTJF)}" fullword ascii
    $s5  = "++;}SMeQgSKrqCq++;} return VEFrxslyVbh}" fullword ascii
    $s6  = "function guXYVFYEZLvycECQjevTwJuXNtcdzkhBVSnjeUeBAWqspGxNwMiwyO(TXtegYNfLterl,sCJCLwcfWaNdoz){ return izfXQ[PsZyh(TXtegYNfLterl[" ascii
    $s7  = "function nBsRyavzljmgfBpKy(OQXow){VEFrxslyVbh= '';SMeQgSKrqCq=(-605+605)/461; while(true){if(SMeQgSKrqCq >= (765+735)/750)break;" ascii
    $s8  = "var hE=new Array(\"2b\",\"27\",\"2f\",\"2f\",\"27\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s9  = "function PsZyh(NDEDIHAooyn,FZtsIurqcjyKR,CyDTJEfu){bvep=parseInt(NDEDIHAooyn,FZtsIurqcjyKR);EglMJ=bvep.toString(CyDTJEfu);return" ascii
    $s10 = "var hE=new Array(\"2b\",\"27\",\"2f\",\"2f\",\"27\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\"," ascii
    $s11 = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function PsZyh(NDEDIHAooyn,FZtsIurqcjyKR,CyDTJEfu){bvep=parseInt(NDEDIHAooyn,FZtsIurqcjyKR);EglMJ=bvep.toString(CyDTJEfu);return" ascii
    $s13 = "QexMxQMYS[SMeQgSKrqCq]=(-630+630)/29; while(true) { if(QexMxQMYS[SMeQgSKrqCq] > OQXow[SMeQgSKrqCq].length-(151+426)/577) { break" ascii
    $s14 = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function guXYVFYEZLvycECQjevTwJuXNtcdzkhBVSnjeUeBAWqspGxNwMiwyO(TXtegYNfLterl,sCJCLwcfWaNdoz){ return izfXQ[PsZyh(TXtegYNfLterl[" ascii
    $s16 = "function nBsRyavzljmgfBpKy(OQXow){VEFrxslyVbh= '';SMeQgSKrqCq=(-605+605)/461; while(true){if(SMeQgSKrqCq >= (765+735)/750)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}