rule sig_20151211_2ad4db1e34719e014a8c8d52a603a73c {
  meta:
    description = "datamaliciousorder - file 20151211_2ad4db1e34719e014a8c8d52a603a73c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dae7c1703452b799d8671fe557b09a679bb88a977b6f10088eec820f40c6e79"

  strings:
    $s1  = "function BnkjshL(OnhDvJFRgVrgLFDMoQZnmntKDWtihFLQiiVU) {return !isNaN(parseFloat(OnhDvJFRgVrgLFDMoQZnmntKDWtihFLQiiVU)) && isFin" ascii
    $s2  = "function BnkjshL(OnhDvJFRgVrgLFDMoQZnmntKDWtihFLQiiVU) {return !isNaN(parseFloat(OnhDvJFRgVrgLFDMoQZnmntKDWtihFLQiiVU)) && isFin" ascii
    $s3  = "function uvstUPGZNvNNchKSo(cQywG){DajnOoONHmO= '';wmRslVcQkdC=(-517+517)/837; while(true){if(wmRslVcQkdC >= (-347+647)/150)break" ascii
    $s4  = "function uvstUPGZNvNNchKSo(cQywG){DajnOoONHmO= '';wmRslVcQkdC=(-517+517)/837; while(true){if(wmRslVcQkdC >= (-347+647)/150)break" ascii
    $s5  = "C]++;}wmRslVcQkdC++;} return DajnOoONHmO}" fullword ascii
    $s6  = ";WtXbmRMRc[wmRslVcQkdC]=(-593+593)/212; while(true) { if(WtXbmRMRc[wmRslVcQkdC] > cQywG[wmRslVcQkdC].length-(138+720)/858) { bre" ascii
    $s7  = "function EqUsrcZRyQivMxPqcirPskmzawVvuyoyxHKSKYfRkDbuNOzpgZSbgb(PtWZWXfKuwpOY,kgqdmRSRfgLSyL){ return jbGHR[cROrj(PtWZWXfKuwpOY[" ascii
    $s8  = "function cROrj(vlwrkVhoOPh,UiryTTFVSALfd,MwbqmlEl){buKI=parseInt(vlwrkVhoOPh,UiryTTFVSALfd);CRsrC=buKI.toString(MwbqmlEl);return" ascii
    $s9  = "var A=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"45\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "var A=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"45\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var t=new Array(\"2b\",\"29\",\"2b\",\"2e\",\"2e\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = " CRsrC;}function yzEZtmwvtIrUKGt(dJHAWcHeAMqukFZXv){eval(dJHAWcHeAMqukFZXv)}" fullword ascii
    $s13 = "function IOnkJFiLgGG(cuNdbBmr,egsajM){return cuNdbBmr.split(egsajM)}" fullword ascii
    $s14 = "function cROrj(vlwrkVhoOPh,UiryTTFVSALfd,MwbqmlEl){buKI=parseInt(vlwrkVhoOPh,UiryTTFVSALfd);CRsrC=buKI.toString(MwbqmlEl);return" ascii
    $s15 = "function EqUsrcZRyQivMxPqcirPskmzawVvuyoyxHKSKYfRkDbuNOzpgZSbgb(PtWZWXfKuwpOY,kgqdmRSRfgLSyL){ return jbGHR[cROrj(PtWZWXfKuwpOY[" ascii
    $s16 = "var t=new Array(\"2b\",\"29\",\"2b\",\"2e\",\"2e\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}