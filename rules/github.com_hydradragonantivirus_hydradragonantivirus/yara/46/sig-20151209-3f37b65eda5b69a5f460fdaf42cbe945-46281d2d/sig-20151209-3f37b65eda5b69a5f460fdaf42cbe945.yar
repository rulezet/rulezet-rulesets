rule sig_20151209_3f37b65eda5b69a5f460fdaf42cbe945 {
  meta:
    description = "datamaliciousorder - file 20151209_3f37b65eda5b69a5f460fdaf42cbe945.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4c6ef03ed89d30db69a4bb40c3ee86af6ba9711d0d3fede6bf016e0c576167"

  strings:
    $s1  = "function WMXJPWo(gCTTaPDJNUudjqvyvMYVcvDneXsJvLfYkjph) {return !isNaN(parseFloat(gCTTaPDJNUudjqvyvMYVcvDneXsJvLfYkjph)) && isFin" ascii
    $s2  = "function WMXJPWo(gCTTaPDJNUudjqvyvMYVcvDneXsJvLfYkjph) {return !isNaN(parseFloat(gCTTaPDJNUudjqvyvMYVcvDneXsJvLfYkjph)) && isFin" ascii
    $s3  = "function DTTBpxtcbMSAQGpQW(CJGNT){BlrfCwTKPuW= '';for(YJfvkFFrooV=(-646+646)/837; YJfvkFFrooV < (320+112)/216; YJfvkFFrooV++) {f" ascii
    $s4  = "function CEBQr(tIxozIbHrju,YSBjkWEzTYCcm,UvkecLUc){rhwY=parseInt(tIxozIbHrju,YSBjkWEzTYCcm);XbPJZ=rhwY.toString(UvkecLUc);return" ascii
    $s5  = "function DTTBpxtcbMSAQGpQW(CJGNT){BlrfCwTKPuW= '';for(YJfvkFFrooV=(-646+646)/837; YJfvkFFrooV < (320+112)/216; YJfvkFFrooV++) {f" ascii
    $s6  = "function liXpoePFCKQ(vsmFsmkg,HzcYoN){return vsmFsmkg.split(HzcYoN)}" fullword ascii
    $s7  = "TDAuAkaL[YJfvkFFrooV]=(-714+714)/993; while(true) { if(fTDAuAkaL[YJfvkFFrooV] > CJGNT[YJfvkFFrooV].length-(-499+698)/199) { brea" ascii
    $s8  = ";}} return BlrfCwTKPuW}" fullword ascii
    $s9  = " XbPJZ;}function WuIHQjgkkWRyhGI(cHCsVQQsWTTbCeguy){eval(cHCsVQQsWTTbCeguy)}" fullword ascii
    $s10 = "function CEBQr(tIxozIbHrju,YSBjkWEzTYCcm,UvkecLUc){rhwY=parseInt(tIxozIbHrju,YSBjkWEzTYCcm);XbPJZ=rhwY.toString(UvkecLUc);return" ascii
    $s11 = "function svMTNgXdaFJIRdzTcXPJiWxDdASFpjsxDLoaQAvzzjbdUjUfqjhZGZ(lnEMpLDNpIzIj,bwSCAzWVtYpRTX){ return Ijffp[CEBQr(lnEMpLDNpIzIj[" ascii
    $s12 = "function svMTNgXdaFJIRdzTcXPJiWxDdASFpjsxDLoaQAvzzjbdUjUfqjhZGZ(lnEMpLDNpIzIj,bwSCAzWVtYpRTX){ return Ijffp[CEBQr(lnEMpLDNpIzIj[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}