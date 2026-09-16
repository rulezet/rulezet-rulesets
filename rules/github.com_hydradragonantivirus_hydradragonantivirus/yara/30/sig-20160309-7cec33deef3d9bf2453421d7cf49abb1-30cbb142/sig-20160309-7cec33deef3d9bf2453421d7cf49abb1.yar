rule sig_20160309_7cec33deef3d9bf2453421d7cf49abb1 {
  meta:
    description = "datamaliciousorder - file 20160309_7cec33deef3d9bf2453421d7cf49abb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ad8eac4ed7880f88fa456132f89c577d535c8a9a08933e629796b391f4a3f8"

  strings:
    $s1  = "return AYDDutD[0] + AYDDutD[2] + AYDDutD[4] + \".F\" + AYDDutD[7] + AYDDutD[9] + AYDDutD[12] + AYDDutD[14];" fullword ascii
    $s2  = "var tC = true  , MhfT = Iyy[7] + Iyy[9] + Iyy[11];" fullword ascii
    $s3  = "var Iyy = (\"2.XMLHTTP RoirIYn RUDcQ XML ream St hKzWmZrZ AD REhQdYk O AHrF D\").split(\" \");" fullword ascii
    $s4  = "DaoKo.open(yLdGg,cJslw,false);" fullword ascii
    $s5  = "var AYDDutD = \"Sc eibogfZ r UhpgAkNQK ipting CbAcSLJ nzI ile TrrJoWcUmWhHgV System Nj WFKZc Obj zpNGhb ect sSllmFM\".split(\" " ascii
    $s6  = "function ILvc(uUvsZ) {" fullword ascii
    $s7  = "function IaJU(MIwfR) {" fullword ascii
    $s8  = "function qGYO(DaoKo,cJslw,yLdGg) {" fullword ascii
    $s9  = "function pyoa(LhOaV) {" fullword ascii
    $s10 = "if (j >= MIwfR.length) {break;}" fullword ascii
    $s11 = "return tFQvCko" fullword ascii
    $s12 = "function EfJIA(zbuEOm) {" fullword ascii
    $s13 = "function DHtLvTna(Zem) {" fullword ascii
    $s14 = "if (OAtKc == 1136-936){return true;} else {return false;}" fullword ascii
    $s15 = "return OGpIW;" fullword ascii
    $s16 = "function ljbc(Eebjr) {" fullword ascii
    $s17 = "function cvTFiEkHj(XqBCo,TPYHx,UCmSU,dsDw) {" fullword ascii
    $s18 = "if(t>=L.length) {break;}" fullword ascii
    $s19 = "return uUvsZ.status;" fullword ascii
    $s20 = "function zVjm(OAtKc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}