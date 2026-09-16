rule sig_20170309_053a4cc9b14ac1233ee7401b1621a0c8 {
  meta:
    description = "datamaliciousorder - file 20170309_053a4cc9b14ac1233ee7401b1621a0c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beabeae3c09de635a3139d4f68ca6d0b77111b8b89956b17bb98ec3d0ae787ec"

  strings:
    $s1  = "wluntaba0 = this[ruspisgi(1) + dzuche(1) + ivbonk(1)];" fullword ascii
    $s2  = "function asuxvyd(ubfoxm) {" fullword ascii
    $s3  = "return anxibji[0];" fullword ascii
    $s4  = "return slagqucwu[0];" fullword ascii
    $s5  = "return oqiwo[0];" fullword ascii
    $s6  = "function uderqa(okoj) {" fullword ascii
    $s7  = "function uzow(telojcy) {" fullword ascii
    $s8  = "function kehes(ynrogu) {" fullword ascii
    $s9  = "return quvli[0];" fullword ascii
    $s10 = "return amfuk[0];" fullword ascii
    $s11 = "function ajvusu(gcetlip) {" fullword ascii
    $s12 = "function aqab(fobemu) {" fullword ascii
    $s13 = "return akgita[0];" fullword ascii
    $s14 = "function urwaztucq(upohadh) {" fullword ascii
    $s15 = "function abyjo(porra) {" fullword ascii
    $s16 = "function osfipp(wqygpu) {" fullword ascii
    $s17 = "function omewnuqj(wwihy) {" fullword ascii
    $s18 = "return odpero[0];" fullword ascii
    $s19 = "return uwbiszag[0];" fullword ascii
    $s20 = "return esahux[0];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}