rule sig_20160419_f6de4606ec0ef64a5f0fcb63b4b56f98 {
  meta:
    description = "datamaliciousorder - file 20160419_f6de4606ec0ef64a5f0fcb63b4b56f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5dcebb81b5f97f5cb4a8fd39a33b860a41c6f518355f3bd9752ac21e4b4fc93"

  strings:
    $s1  = "var sb = true  , xwuZ = TQR[7] + TQR[9] + TQR[11];" fullword ascii
    $s2  = "return lewyVeQ[0] + lewyVeQ[2] + lewyVeQ[4] + \".F\" + lewyVeQ[7] + lewyVeQ[9] + lewyVeQ[12] + lewyVeQ[14];" fullword ascii
    $s3  = "var TQR = (\"2.XMLHTTP GuPsipK YArAv XML ream St TnoTfVKa AD AYFFGId O iYNE D\").split(\" \");" fullword ascii
    $s4  = "RcIH.open(dxGXH,tnWKq,false);" fullword ascii
    $s5  = "return new ActiveXObject(gdKG);" fullword ascii
    $s6  = "function dHQK(iOqKL) {" fullword ascii
    $s7  = "return rWDIgZK[0];" fullword ascii
    $s8  = "return XUvfd;" fullword ascii
    $s9  = "function PSJRlCE(PHYZ) {" fullword ascii
    $s10 = "function QrEN(LSnwd) {" fullword ascii
    $s11 = "function Nqztf(ynSSjwPL,etCZ) {" fullword ascii
    $s12 = "function qrsd(UZaKo) {" fullword ascii
    $s13 = "function qUNYnPm(RKnj,NWNEy) {" fullword ascii
    $s14 = "return DRiSmGC;" fullword ascii
    $s15 = "function bdtOe(apG,sXxFb) {" fullword ascii
    $s16 = "return hDijQh[aUjP[422-422]]=353-353;" fullword ascii
    $s17 = "function vGYdQEvB(GIg) {" fullword ascii
    $s18 = "return PHYZ[ThWnDyB[0]+ThWnDyB[1]];" fullword ascii
    $s19 = "function INLSEI(JWJh,wNipIB) {" fullword ascii
    $s20 = "function fCug(yCiuS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}