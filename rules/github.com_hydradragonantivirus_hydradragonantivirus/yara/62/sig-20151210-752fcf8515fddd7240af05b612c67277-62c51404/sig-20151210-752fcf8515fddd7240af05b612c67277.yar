rule sig_20151210_752fcf8515fddd7240af05b612c67277 {
  meta:
    description = "datamaliciousorder - file 20151210_752fcf8515fddd7240af05b612c67277.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "599c0be73bf9d408ba39b24b2a7a310a958be0964fc81bd471dcba7acd40d3ea"

  strings:
    $s1  = "function AfxQree(XmtwqFLomiwYldNHurrcpGfxREAwUOpekGAo) {return !isNaN(parseFloat(XmtwqFLomiwYldNHurrcpGfxREAwUOpekGAo)) && isFin" ascii
    $s2  = "function AfxQree(XmtwqFLomiwYldNHurrcpGfxREAwUOpekGAo) {return !isNaN(parseFloat(XmtwqFLomiwYldNHurrcpGfxREAwUOpekGAo)) && isFin" ascii
    $s3  = "kvGydqU=(-578+578)/536;while(true){if(kvGydqU>=(6815+737)/59){break;}GXZQPAvffQUMB[kvGydqU]=String.fromCharCode(kvGydqU);kvGydqU" ascii
    $s4  = "function YrBrOYPKFIB(gtwxOhuv,yyVfmy){return gtwxOhuv.split(yyVfmy)}" fullword ascii
    $s5  = "kvGydqU=(-578+578)/536;while(true){if(kvGydqU>=(6815+737)/59){break;}GXZQPAvffQUMB[kvGydqU]=String.fromCharCode(kvGydqU);kvGydqU" ascii
    $s6  = "CGuFMWev[ilaLEhUvXVu]=(-350+350)/659; while(true) { if(JCGuFMWev[ilaLEhUvXVu] > ZfgUi[ilaLEhUvXVu].length-(-225+998)/773) { brea" ascii
    $s7  = "+;}} return PpgHZAWoclp}" fullword ascii
    $s8  = "function gYaPO(pAxLOpfDILv,FrzUsnDgKJuOs,tKbMIfZa){SgGS=parseInt(pAxLOpfDILv,FrzUsnDgKJuOs);CUVmL=SgGS.toString(tKbMIfZa);return" ascii
    $s9  = "function aeDUlELikbFEmrKAcYrAxevWJwTyIwJNIfuhEYtiWlAgrnUAPYUibq(JRrlLQwYIFuHo,LGDIqfeyGcIrLH){ return GXZQPAvffQUMB[gYaPO(JRrlLQ" ascii
    $s10 = " CUVmL;}function vIwtJaUlKyIIsEO(UDqYzNpvTTOpYDbHT){eval(UDqYzNpvTTOpYDbHT)}" fullword ascii
    $s11 = "function aeDUlELikbFEmrKAcYrAxevWJwTyIwJNIfuhEYtiWlAgrnUAPYUibq(JRrlLQwYIFuHo,LGDIqfeyGcIrLH){ return GXZQPAvffQUMB[gYaPO(JRrlLQ" ascii
    $s12 = "function gYaPO(pAxLOpfDILv,FrzUsnDgKJuOs,tKbMIfZa){SgGS=parseInt(pAxLOpfDILv,FrzUsnDgKJuOs);CUVmL=SgGS.toString(tKbMIfZa);return" ascii
    $s13 = "function gALrOlCaUyThSfQZj(ZfgUi){PpgHZAWoclp= '';for(ilaLEhUvXVu=(-482+482)/145; ilaLEhUvXVu < (476+730)/603; ilaLEhUvXVu++) {J" ascii
    $s14 = "function gALrOlCaUyThSfQZj(ZfgUi){PpgHZAWoclp= '';for(ilaLEhUvXVu=(-482+482)/145; ilaLEhUvXVu < (476+730)/603; ilaLEhUvXVu++) {J" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}