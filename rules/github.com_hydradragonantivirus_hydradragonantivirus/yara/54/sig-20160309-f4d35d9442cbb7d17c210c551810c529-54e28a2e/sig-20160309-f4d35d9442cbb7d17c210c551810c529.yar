rule sig_20160309_f4d35d9442cbb7d17c210c551810c529 {
  meta:
    description = "datamaliciousorder - file 20160309_f4d35d9442cbb7d17c210c551810c529.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe4d46044c95d04252ad99bdd58f6571244443ec4bfdc5352d2964d784a8938"

  strings:
    $s1  = "var FkMhhiB = \"Sc eNiLgZP r YNPgnFzkS ipting eGtxIeX GrV ile VAVsWvxkDyfKtw System ZC rKxby Obj oXEiin ect pYRaoBe\".split(\" " ascii
    $s2  = "return FkMhhiB[0] + FkMhhiB[2] + FkMhhiB[4] + \".F\" + FkMhhiB[7] + FkMhhiB[9] + FkMhhiB[12] + FkMhhiB[14];" fullword ascii
    $s3  = "var TE = true  , YecB = XbH[7] + XbH[9] + XbH[11];" fullword ascii
    $s4  = "var XbH = (\"2.XMLHTTP CsffDyr vwhBO XML ream St DSOVsqyC AD yFgALHT O WLry D\").split(\" \");" fullword ascii
    $s5  = "PgfiX.open(JIDOI,vWiTI,false);" fullword ascii
    $s6  = "return KFtKa;" fullword ascii
    $s7  = "if (d >= OyArO.length) {break;}" fullword ascii
    $s8  = "function mdqUjXbe() {" fullword ascii
    $s9  = "function XuJg(ZdAyh) {" fullword ascii
    $s10 = "return new ActiveXObject(jEgZkL);" fullword ascii
    $s11 = "function FvgxXUt(Gtjn,ruccz) {" fullword ascii
    $s12 = "return FWC.size;" fullword ascii
    $s13 = "function WhcD(wJohi) {" fullword ascii
    $s14 = "if (HDdHN == 1108-908){return true;} else {return false;}" fullword ascii
    $s15 = "function seKH(kAHyA) {" fullword ascii
    $s16 = "return biSG.responseBody;" fullword ascii
    $s17 = "function uWAz(OyArO) {" fullword ascii
    $s18 = "function NiQE(Xhxcy) {" fullword ascii
    $s19 = "function sBWjYTAyK(dYnNN,ioVZx,tXXce,yOoL) {" fullword ascii
    $s20 = "function RLME(PgfiX,vWiTI,JIDOI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}