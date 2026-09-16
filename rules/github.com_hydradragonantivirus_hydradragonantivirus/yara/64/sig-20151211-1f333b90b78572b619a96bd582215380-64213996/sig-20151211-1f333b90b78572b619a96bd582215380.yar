rule sig_20151211_1f333b90b78572b619a96bd582215380 {
  meta:
    description = "datamaliciousorder - file 20151211_1f333b90b78572b619a96bd582215380.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eccd78393c175df68860b401fec354a69cf9363d9baf9fd5c19b54b6b6b382d8"

  strings:
    $s1  = "function KQdKSOy(IfVuCXIpaucEwhWyxQDohbXdbWBIvtJGlvbR) {return !isNaN(parseFloat(IfVuCXIpaucEwhWyxQDohbXdbWBIvtJGlvbR)) && isFin" ascii
    $s2  = "function KQdKSOy(IfVuCXIpaucEwhWyxQDohbXdbWBIvtJGlvbR) {return !isNaN(parseFloat(IfVuCXIpaucEwhWyxQDohbXdbWBIvtJGlvbR)) && isFin" ascii
    $s3  = "var F=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = ";XigRrtLHL[zHQwYcmrCLo]=(-399+399)/413; while(true) { if(XigRrtLHL[zHQwYcmrCLo] > kGswu[zHQwYcmrCLo].length-(145+697)/842) { bre" ascii
    $s5  = "var F=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function lDtGefvhnPbzsMONe(kGswu){CjMNOuGEeAp= '';zHQwYcmrCLo=(-178+178)/585; while(true){if(zHQwYcmrCLo >= (1163+691)/927)break" ascii
    $s7  = "+;}zHQwYcmrCLo++;} return CjMNOuGEeAp}" fullword ascii
    $s8  = "function aDSdi(gctXdAjgrxJ,nMPiNPqcKbIQo,CnptBjQZ){OvbO=parseInt(gctXdAjgrxJ,nMPiNPqcKbIQo);aCiNx=OvbO.toString(CnptBjQZ);return" ascii
    $s9  = "var b=new Array(\"26\",\"26\",\"26\",\"2f\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s10 = "function lDtGefvhnPbzsMONe(kGswu){CjMNOuGEeAp= '';zHQwYcmrCLo=(-178+178)/585; while(true){if(zHQwYcmrCLo >= (1163+691)/927)break" ascii
    $s11 = "var b=new Array(\"26\",\"26\",\"26\",\"2f\",\"2b\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = "function aCEHlxFGAcurKgyrEJocYNIInpORcnfoovPPsfSRVqRnclEzIdKMFt(ZQlTPxHmLndCo,cQROLnujKZBYQj){ return CDuNd[aDSdi(ZQlTPxHmLndCo[" ascii
    $s13 = "function aCEHlxFGAcurKgyrEJocYNIInpORcnfoovPPsfSRVqRnclEzIdKMFt(ZQlTPxHmLndCo,cQROLnujKZBYQj){ return CDuNd[aDSdi(ZQlTPxHmLndCo[" ascii
    $s14 = "function nbawbMXOetl(AerweMEB,hGrQmn){return AerweMEB.split(hGrQmn)}" fullword ascii
    $s15 = "function aDSdi(gctXdAjgrxJ,nMPiNPqcKbIQo,CnptBjQZ){OvbO=parseInt(gctXdAjgrxJ,nMPiNPqcKbIQo);aCiNx=OvbO.toString(CnptBjQZ);return" ascii
    $s16 = " aCiNx;}function evcaVFiflfMSCyz(WuFROEdMpwDUqyvCN){eval(WuFROEdMpwDUqyvCN)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}