rule sig_20160313_bb564fde8aa86f762cab5996ba493711 {
  meta:
    description = "datamaliciousorder - file 20160313_bb564fde8aa86f762cab5996ba493711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0264dc3477214944c2c9f08b7c8963f301e5e0a89ee3a43483e4c6ae0d3036b2"

  strings:
    $s1  = "var Vl = true  , igXS = dge[7] + dge[9] + dge[11];" fullword ascii
    $s2  = "return XhYJubu[0] + XhYJubu[2] + XhYJubu[4] + \".F\" + XhYJubu[7] + XhYJubu[9] + XhYJubu[12] + XhYJubu[14];" fullword ascii
    $s3  = "gjcLh.open(pOCrI,mocbc,false);" fullword ascii
    $s4  = "var XhYJubu = \"Sc ESASlpa r qPmFaRZgS ipting crgUwJB vKF ile jzZcvrQvUcgSGo System kh TpLmm Obj ivXdlB ect UvQZhCx\".split(\" " ascii
    $s5  = "function DFOS(ZFMQu) {" fullword ascii
    $s6  = "function DYVR(NtJed) {" fullword ascii
    $s7  = "function rmmdJCy(HojB,KWgTq) {" fullword ascii
    $s8  = "if (jIIvu > 190523-956){return true;} else {return false;}" fullword ascii
    $s9  = "function UVgC(gjcLh,mocbc,pOCrI) {" fullword ascii
    $s10 = "return Ukp.size;" fullword ascii
    $s11 = "return phBItq.position=452-452;" fullword ascii
    $s12 = "function UEfVoeLFV() {" fullword ascii
    $s13 = "function VonqO(phBItq) {" fullword ascii
    $s14 = "function PYUjJTjG() {" fullword ascii
    $s15 = "if (AfjvL == 1195-995){return true;} else {return false;}" fullword ascii
    $s16 = "function iFhchcCx(Ukp) {" fullword ascii
    $s17 = "function ieiF(eYHuw,ZccJN) {" fullword ascii
    $s18 = "function fACW(gyidy) {" fullword ascii
    $s19 = "return zWTNX;" fullword ascii
    $s20 = "function BCZoC(ihKLyM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}