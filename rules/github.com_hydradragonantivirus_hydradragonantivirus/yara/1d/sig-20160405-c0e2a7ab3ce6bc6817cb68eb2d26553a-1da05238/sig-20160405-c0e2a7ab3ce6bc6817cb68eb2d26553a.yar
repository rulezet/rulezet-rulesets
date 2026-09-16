rule sig_20160405_c0e2a7ab3ce6bc6817cb68eb2d26553a {
  meta:
    description = "datamaliciousorder - file 20160405_c0e2a7ab3ce6bc6817cb68eb2d26553a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5f25ce665dfebed5485743e5637ed91beaebf6755e191f415ebfb3971b28c32"

  strings:
    $s1  = "return zgRhJaP[0] + zgRhJaP[2] + zgRhJaP[4] + \".F\" + zgRhJaP[7] + zgRhJaP[9] + zgRhJaP[12] + zgRhJaP[14];" fullword ascii
    $s2  = "var KX = true  , witX = rga[7] + rga[9] + rga[11];" fullword ascii
    $s3  = "yeDF.open(GKwzA,dexVZ,false);" fullword ascii
    $s4  = "var rga = (\"2.XMLHTTP jripxLN nePkF XML ream St pFsUqCWg AD jBnAuzD O Ktmf D\").split(\" \");" fullword ascii
    $s5  = "function gsJX(akqbz) {" fullword ascii
    $s6  = "return bZMzj;" fullword ascii
    $s7  = "return new ActiveXObject(uNlG);" fullword ascii
    $s8  = "function TgnHWx(lkqB,rPEZeI) {" fullword ascii
    $s9  = "function aUnwnQtP(MhQ) {" fullword ascii
    $s10 = "function gQEv(ZYFqT) {" fullword ascii
    $s11 = "Nbu = D; break; " fullword ascii
    $s12 = "if (akqbz == 435-235){return true;} else {return false;}" fullword ascii
    $s13 = "return RFeK[fDuZfr[0]];" fullword ascii
    $s14 = "function lViwjbrdR(ELcQQPKuCEg) {" fullword ascii
    $s15 = "function kWac(IzQxG,xYjEJ) {" fullword ascii
    $s16 = "function PVlnZX(TdUZTvA) {" fullword ascii
    $s17 = "function lhoC(qSoOW) {" fullword ascii
    $s18 = "function HipzF(CybaCT) {" fullword ascii
    $s19 = "function iFlGozn(HpBQ,jzjqd) {" fullword ascii
    $s20 = "function eypCUibo(nVgG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}