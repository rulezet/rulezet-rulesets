rule sig_20160308_a11cd2ef96516d815f48054f3ecd0a67 {
  meta:
    description = "datamaliciousorder - file 20160308_a11cd2ef96516d815f48054f3ecd0a67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "722a2dcca37a1d33c48a69bef17d2d39d88706a16d9dd641fcb1b839e14b9e6f"

  strings:
    $s1  = "return kAAUcTk[0] + kAAUcTk[2] + kAAUcTk[4] + \".F\" + kAAUcTk[7] + kAAUcTk[9] + kAAUcTk[12] + kAAUcTk[14];" fullword ascii
    $s2  = "var cU = true  , YNez = vLL[7] + vLL[9] + vLL[11];" fullword ascii
    $s3  = "FFqYq.open(zFZCB,dXODf,false);" fullword ascii
    $s4  = "var kAAUcTk = \"Sc CZkrZiM r bdOMVKIIW ipting cilKohC uOi ile aofddoTsYlNetK System oZ bHgqt Obj kQrlaw ect MDYteuS\".split(\" " ascii
    $s5  = "var vLL = (\"2.XMLHTTP REAZeJl WtvEA XML ream St TtHnBMHG AD TDMaHyn O ftIF D\").split(\" \");" fullword ascii
    $s6  = "function KitL(PjRey) {" fullword ascii
    $s7  = "if (H >= eMeuU.length) {break;}" fullword ascii
    $s8  = "return new ActiveXObject(owZoFx);" fullword ascii
    $s9  = "if (((new Date())>0,730578888)) {" fullword ascii
    $s10 = "function UEDnjcnDq(OEnDzuyPMFY) {" fullword ascii
    $s11 = "function dhUhSqVk() {" fullword ascii
    $s12 = "if (dcCBp > 151624-213){return true;} else {return false;}" fullword ascii
    $s13 = "function xxpi(haRVV) {" fullword ascii
    $s14 = "if (PjRey == 428-228){return true;} else {return false;}" fullword ascii
    $s15 = "mIj = y; break; " fullword ascii
    $s16 = "function NFAS(agcUJ) {" fullword ascii
    $s17 = "return Mmiio.status;" fullword ascii
    $s18 = "function vPkKvbrj(Udd) {" fullword ascii
    $s19 = "return elROF;" fullword ascii
    $s20 = "return Udd.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}