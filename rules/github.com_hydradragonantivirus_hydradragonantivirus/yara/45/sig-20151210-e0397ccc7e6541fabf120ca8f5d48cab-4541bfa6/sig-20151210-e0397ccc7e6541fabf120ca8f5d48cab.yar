rule sig_20151210_e0397ccc7e6541fabf120ca8f5d48cab {
  meta:
    description = "datamaliciousorder - file 20151210_e0397ccc7e6541fabf120ca8f5d48cab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90856a5968e526cc10c145ee30660686e92f10ea697c9d293abd3b4c9a5a65d3"

  strings:
    $s1  = "function zOKAGEtXLRh(RGsPCxPp,iOuXmg){return RGsPCxPp.split(iOuXmg)}" fullword ascii
    $s2  = "function UVuEedA(DOexnGBsVxkolQPTSCdaLYrJZhzgwjbDNSOQ) {return !isNaN(parseFloat(DOexnGBsVxkolQPTSCdaLYrJZhzgwjbDNSOQ)) && isFin" ascii
    $s3  = "function UVuEedA(DOexnGBsVxkolQPTSCdaLYrJZhzgwjbDNSOQ) {return !isNaN(parseFloat(DOexnGBsVxkolQPTSCdaLYrJZhzgwjbDNSOQ)) && isFin" ascii
    $s4  = "function wlgVjkKoZCQeWHGJb(HZsms){yQoHruunErB= '';for(QFaxKMpwpkQ=(-360+360)/72; QFaxKMpwpkQ < (571+465)/518; QFaxKMpwpkQ++) {Wd" ascii
    $s5  = "function PceeJOyswFJQzeQdKUZZOmNaHnWrgVjlDWXCjMQCfQfSxEsFRCeZqm(dOMLevzeEPWyx,fTIBhPhXBEvcXn){ return tSDWDcoqdTxEl[QClFk(dOMLev" ascii
    $s6  = "function QClFk(IiiyAutlXrc,UpPeEUetPwgWA,grLbrSwM){bddV=parseInt(IiiyAutlXrc,UpPeEUetPwgWA);ssymx=bddV.toString(grLbrSwM);return" ascii
    $s7  = "JCCJvZf=(-389+389)/199;while(true){if(JCCJvZf>=(14357+619)/117){break;}tSDWDcoqdTxEl[JCCJvZf]=String.fromCharCode(JCCJvZf);JCCJv" ascii
    $s8  = "function wlgVjkKoZCQeWHGJb(HZsms){yQoHruunErB= '';for(QFaxKMpwpkQ=(-360+360)/72; QFaxKMpwpkQ < (571+465)/518; QFaxKMpwpkQ++) {Wd" ascii
    $s9  = " ssymx;}function ZtQwHNKyHlilVlW(eHIAmvMKLdtXDRzUe){eval(eHIAmvMKLdtXDRzUe)}" fullword ascii
    $s10 = "bhtcbuS[QFaxKMpwpkQ]=(-411+411)/980; while(true) { if(WdbhtcbuS[QFaxKMpwpkQ] > HZsms[QFaxKMpwpkQ].length-(739+248)/987) { break;" ascii
    $s11 = "JCCJvZf=(-389+389)/199;while(true){if(JCCJvZf>=(14357+619)/117){break;}tSDWDcoqdTxEl[JCCJvZf]=String.fromCharCode(JCCJvZf);JCCJv" ascii
    $s12 = "function QClFk(IiiyAutlXrc,UpPeEUetPwgWA,grLbrSwM){bddV=parseInt(IiiyAutlXrc,UpPeEUetPwgWA);ssymx=bddV.toString(grLbrSwM);return" ascii
    $s13 = ";}} return yQoHruunErB}" fullword ascii
    $s14 = "function PceeJOyswFJQzeQdKUZZOmNaHnWrgVjlDWXCjMQCfQfSxEsFRCeZqm(dOMLevzeEPWyx,fTIBhPhXBEvcXn){ return tSDWDcoqdTxEl[QClFk(dOMLev" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}