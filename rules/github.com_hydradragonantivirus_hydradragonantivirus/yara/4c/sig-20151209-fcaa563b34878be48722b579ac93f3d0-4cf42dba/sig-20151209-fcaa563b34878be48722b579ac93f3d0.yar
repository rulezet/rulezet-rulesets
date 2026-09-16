rule sig_20151209_fcaa563b34878be48722b579ac93f3d0 {
  meta:
    description = "datamaliciousorder - file 20151209_fcaa563b34878be48722b579ac93f3d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7705e10616157a514a55b194abc841beb1c97ae490ca26c4d2132ee3f270ceb"

  strings:
    $s1  = "function qqNIfBURHdZvqaLdp(gOwcC){nLfpwELFjUA= '';for(RAmwyhUAJNU=(-172+172)/269; RAmwyhUAJNU < (814+848)/831; RAmwyhUAJNU++) {U" ascii
    $s2  = "function QMJULXy(YuXIrfbPgdSTGjIiozGpfllSgDggTMHykvNh) {return !isNaN(parseFloat(YuXIrfbPgdSTGjIiozGpfllSgDggTMHykvNh)) && isFin" ascii
    $s3  = "function QMJULXy(YuXIrfbPgdSTGjIiozGpfllSgDggTMHykvNh) {return !isNaN(parseFloat(YuXIrfbPgdSTGjIiozGpfllSgDggTMHykvNh)) && isFin" ascii
    $s4  = "function HazcpzlqqJmmwsGjXjMIBdjQTFCKUtHGgiEgAXvDRQzKRBVRunLsjm(tTDoKKtaNsQxl,TJeXMKyryFtEwa){ return gSxkj[TScYu(tTDoKKtaNsQxl[" ascii
    $s5  = "function HazcpzlqqJmmwsGjXjMIBdjQTFCKUtHGgiEgAXvDRQzKRBVRunLsjm(tTDoKKtaNsQxl,TJeXMKyryFtEwa){ return gSxkj[TScYu(tTDoKKtaNsQxl[" ascii
    $s6  = "KlNRGPCZ[RAmwyhUAJNU]=(-823+823)/628; while(true) { if(UKlNRGPCZ[RAmwyhUAJNU] > gOwcC[RAmwyhUAJNU].length-(369+370)/739) { break" ascii
    $s7  = " TVksZ;}function SnCkLWiBCSfZLLb(cznpxpClQEDKrPKgP){eval(cznpxpClQEDKrPKgP)}" fullword ascii
    $s8  = "function TScYu(LtQTpWMLOyr,hPjqTpsTZHOZD,xciSzhrE){LVbB=parseInt(LtQTpWMLOyr,hPjqTpsTZHOZD);TVksZ=LVbB.toString(xciSzhrE);return" ascii
    $s9  = "function QcOCdeYftJu(OESzGnNy,agArmb){return OESzGnNy.split(agArmb)}" fullword ascii
    $s10 = ";}} return nLfpwELFjUA}" fullword ascii
    $s11 = "function TScYu(LtQTpWMLOyr,hPjqTpsTZHOZD,xciSzhrE){LVbB=parseInt(LtQTpWMLOyr,hPjqTpsTZHOZD);TVksZ=LVbB.toString(xciSzhrE);return" ascii
    $s12 = "function qqNIfBURHdZvqaLdp(gOwcC){nLfpwELFjUA= '';for(RAmwyhUAJNU=(-172+172)/269; RAmwyhUAJNU < (814+848)/831; RAmwyhUAJNU++) {U" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}