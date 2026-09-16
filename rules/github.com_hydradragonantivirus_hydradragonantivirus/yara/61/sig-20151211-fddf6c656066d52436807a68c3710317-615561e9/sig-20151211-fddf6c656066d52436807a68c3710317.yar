rule sig_20151211_fddf6c656066d52436807a68c3710317 {
  meta:
    description = "datamaliciousorder - file 20151211_fddf6c656066d52436807a68c3710317.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeebac199de4bfa0cd578f0a724e297bc408c178b44ff235ecb982016647a454"

  strings:
    $s1  = "function LfHURgt(rPiCtVvbGTDXXrBmbzadYYMSZYsdXlqCedhs) {return !isNaN(parseFloat(rPiCtVvbGTDXXrBmbzadYYMSZYsdXlqCedhs)) && isFin" ascii
    $s2  = "function LfHURgt(rPiCtVvbGTDXXrBmbzadYYMSZYsdXlqCedhs) {return !isNaN(parseFloat(rPiCtVvbGTDXXrBmbzadYYMSZYsdXlqCedhs)) && isFin" ascii
    $s3  = "function qgIuPkgiQdDdYRSFy(DoIjG){FpmaNIEYVEn= '';jydPkJZgMmq=(-923+923)/900; while(true){if(jydPkJZgMmq >= (501+397)/449)break;" ascii
    $s4  = "var u=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "var d=new Array(\"2d\",\"26\",\"26\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s6  = "var u=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function vXrlE(oywzCqtGqwm,WiYKUATbJqQHG,dCOXguAL){UZuG=parseInt(oywzCqtGqwm,WiYKUATbJqQHG);ixEfu=UZuG.toString(dCOXguAL);return" ascii
    $s8  = "function BDcJooriAmrgsvxubzFgWYUthtUVJngelLLXJacNPUHKazVGqfEIWq(lznrazJucEDNP,UAKsjifKCiVHQl){ return JzpsE[vXrlE(lznrazJucEDNP[" ascii
    $s9  = "function vXrlE(oywzCqtGqwm,WiYKUATbJqQHG,dCOXguAL){UZuG=parseInt(oywzCqtGqwm,WiYKUATbJqQHG);ixEfu=UZuG.toString(dCOXguAL);return" ascii
    $s10 = " ixEfu;}function MxFBsatrIKiRifW(iqRzgECbrdGbUjaiz){eval(iqRzgECbrdGbUjaiz)}" fullword ascii
    $s11 = "]++;}jydPkJZgMmq++;} return FpmaNIEYVEn}" fullword ascii
    $s12 = "oHTqfJmEn[jydPkJZgMmq]=(-625+625)/675; while(true) { if(oHTqfJmEn[jydPkJZgMmq] > DoIjG[jydPkJZgMmq].length-(-22+326)/304) { brea" ascii
    $s13 = "function qgIuPkgiQdDdYRSFy(DoIjG){FpmaNIEYVEn= '';jydPkJZgMmq=(-923+923)/900; while(true){if(jydPkJZgMmq >= (501+397)/449)break;" ascii
    $s14 = "function BDcJooriAmrgsvxubzFgWYUthtUVJngelLLXJacNPUHKazVGqfEIWq(lznrazJucEDNP,UAKsjifKCiVHQl){ return JzpsE[vXrlE(lznrazJucEDNP[" ascii
    $s15 = "function xftuSQWzzcV(fIWBAYEE,WUEYQi){return fIWBAYEE.split(WUEYQi)}" fullword ascii
    $s16 = "var d=new Array(\"2d\",\"26\",\"26\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}