rule sig_20151210_ecbb8a372c26f39e2b3647814844254a {
  meta:
    description = "datamaliciousorder - file 20151210_ecbb8a372c26f39e2b3647814844254a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e96a72f7cfb01bf2eb3cf82d7a97e1d0377d68ea7bb3847f0a9a90bc1c72e786"

  strings:
    $s1  = "function lQxNaPJ(JJgRnrOJuEYsqqUvdSfAwITYRbbMtsoMrEPa) {return !isNaN(parseFloat(JJgRnrOJuEYsqqUvdSfAwITYRbbMtsoMrEPa)) && isFin" ascii
    $s2  = "function lQxNaPJ(JJgRnrOJuEYsqqUvdSfAwITYRbbMtsoMrEPa) {return !isNaN(parseFloat(JJgRnrOJuEYsqqUvdSfAwITYRbbMtsoMrEPa)) && isFin" ascii
    $s3  = " zmuix;}function ImsRCcMNUzhOKvQ(oHMJYIHVBEZuERKuV){eval(oHMJYIHVBEZuERKuV)}" fullword ascii
    $s4  = "function zcFQCVNvvpFmPfVzE(fmYao){jnIVERIieRV= '';for(LIckpaGFXmo=(-30+30)/561; LIckpaGFXmo < (617+87)/352; LIckpaGFXmo++) {bZDk" ascii
    $s5  = "function MTPCv(sOAKYsUkyWM,wVuQFvsbKiEKm,ZMfLHjtj){Wzbi=parseInt(sOAKYsUkyWM,wVuQFvsbKiEKm);zmuix=Wzbi.toString(ZMfLHjtj);return" ascii
    $s6  = "function OzihUDyEXCpUsuVFDOonoJSvcroITTAhwVmWgEMTaFWXIAXcVJXunr(MyTpcGVvpClpa,hnkqVlNUhTokzd){ return kJbWm[MTPCv(MyTpcGVvpClpa[" ascii
    $s7  = "function VAZMSDKkQyW(EUqfXDWV,ApkZqc){return EUqfXDWV.split(ApkZqc)}" fullword ascii
    $s8  = "function OzihUDyEXCpUsuVFDOonoJSvcroITTAhwVmWgEMTaFWXIAXcVJXunr(MyTpcGVvpClpa,hnkqVlNUhTokzd){ return kJbWm[MTPCv(MyTpcGVvpClpa[" ascii
    $s9  = "function MTPCv(sOAKYsUkyWM,wVuQFvsbKiEKm,ZMfLHjtj){Wzbi=parseInt(sOAKYsUkyWM,wVuQFvsbKiEKm);zmuix=Wzbi.toString(ZMfLHjtj);return" ascii
    $s10 = "Vpnap[LIckpaGFXmo]=(-176+176)/565; while(true) { if(bZDkVpnap[LIckpaGFXmo] > fmYao[LIckpaGFXmo].length-(-679+923)/244) { break; " ascii
    $s11 = "function zcFQCVNvvpFmPfVzE(fmYao){jnIVERIieRV= '';for(LIckpaGFXmo=(-30+30)/561; LIckpaGFXmo < (617+87)/352; LIckpaGFXmo++) {bZDk" ascii
    $s12 = " return jnIVERIieRV}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}