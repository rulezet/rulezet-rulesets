rule sig_20151210_919177e68e3c9c4d65cc630497b2d269 {
  meta:
    description = "datamaliciousorder - file 20151210_919177e68e3c9c4d65cc630497b2d269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4ca654bb226879ae532e0c8a1037ce3a49c31bbae0d465b48c4ae6d746ce675"

  strings:
    $s1  = "function SqDJmTp(xPDrLtdiDfeYKcHmvDouZBttvqilEDDhVMea) {return !isNaN(parseFloat(xPDrLtdiDfeYKcHmvDouZBttvqilEDDhVMea)) && isFin" ascii
    $s2  = "function SqDJmTp(xPDrLtdiDfeYKcHmvDouZBttvqilEDDhVMea) {return !isNaN(parseFloat(xPDrLtdiDfeYKcHmvDouZBttvqilEDDhVMea)) && isFin" ascii
    $s3  = " WVeis;}function LmPACWWlTlAnkoj(QDNQZmrJQazzVIkcR){eval(QDNQZmrJQazzVIkcR)}" fullword ascii
    $s4  = "DNmLRMS=(-726+726)/820;while(true){if(DNmLRMS>=(9624+744)/81){break;}LDfqlcyWJXnzG[DNmLRMS]=String.fromCharCode(DNmLRMS);DNmLRMS" ascii
    $s5  = "function IgSafpKeJLLsssEATdWNeBOGPRYqLqloOYioWNXzQlKtefrZgONGSg(ugCGVdDojwHUb,eXXCImpnqSnlzR){ return LDfqlcyWJXnzG[Pakuo(ugCGVd" ascii
    $s6  = "function WxuqrijzFQSVbKONf(NKpni){bXuHyoEGrdf= '';for(OrHapAsngwa=(-530+530)/939; OrHapAsngwa < (-345+433)/44; OrHapAsngwa++) {U" ascii
    $s7  = "XRudYkyX[OrHapAsngwa]=(-321+321)/397; while(true) { if(UXRudYkyX[OrHapAsngwa] > NKpni[OrHapAsngwa].length-(302+382)/684) { break" ascii
    $s8  = "} return bXuHyoEGrdf}" fullword ascii
    $s9  = "function ILdwYGUdVYX(oOfekZAg,AVszmV){return oOfekZAg.split(AVszmV)}" fullword ascii
    $s10 = "DNmLRMS=(-726+726)/820;while(true){if(DNmLRMS>=(9624+744)/81){break;}LDfqlcyWJXnzG[DNmLRMS]=String.fromCharCode(DNmLRMS);DNmLRMS" ascii
    $s11 = "function Pakuo(IKSnursIBAs,hJUtSbSjNApII,DegVyoZO){QWqc=parseInt(IKSnursIBAs,hJUtSbSjNApII);WVeis=QWqc.toString(DegVyoZO);return" ascii
    $s12 = "function Pakuo(IKSnursIBAs,hJUtSbSjNApII,DegVyoZO){QWqc=parseInt(IKSnursIBAs,hJUtSbSjNApII);WVeis=QWqc.toString(DegVyoZO);return" ascii
    $s13 = "function IgSafpKeJLLsssEATdWNeBOGPRYqLqloOYioWNXzQlKtefrZgONGSg(ugCGVdDojwHUb,eXXCImpnqSnlzR){ return LDfqlcyWJXnzG[Pakuo(ugCGVd" ascii
    $s14 = "function WxuqrijzFQSVbKONf(NKpni){bXuHyoEGrdf= '';for(OrHapAsngwa=(-530+530)/939; OrHapAsngwa < (-345+433)/44; OrHapAsngwa++) {U" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}