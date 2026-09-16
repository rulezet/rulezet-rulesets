rule sig_20160305_ab131049bc7d81c5f30bb46c7ad746f3 {
  meta:
    description = "datamaliciousorder - file 20160305_ab131049bc7d81c5f30bb46c7ad746f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75b9e7ae11a069d9fe05f24c17e15972ee55098112e3db8aafc5c1c9934a5971"

  strings:
    $s1  = "var OuFIf = \"uUpOIZ Lpg pt.Shell CcFBlwv Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var aw = true  , mDOU = DFG[7] + \"\" + DFG[9];" fullword ascii
    $s3  = "var DFG = (vfC + \"TTP\" + \" XzJDkMj ZXmiA XML ream St nWPbLybD AD pJmSEQF OD\").split(\" \");" fullword ascii
    $s4  = "return LrXnCzJ[0] + LrXnCzJ[2] + LrXnCzJ[4] + \".F\" + LrXnCzJ[7] + LrXnCzJ[9] + LrXnCzJ[12] + LrXnCzJ[14];" fullword ascii
    $s5  = "var LrXnCzJ = \"Sc TJUkiTN r yOnDbkrED ipting LKaayFz IiB ile CIaOPMkOAzDNhf System uW BwpzE Obj MeCLUw ect PghzskC\".split(\" " ascii
    $s6  = "QQbVc.open(QRujK,MuDYz,false);" fullword ascii
    $s7  = "return qpWJ.responseBody;" fullword ascii
    $s8  = "if (Tgawz == 717-517){return true;} else {return false;}" fullword ascii
    $s9  = "function WbQvqsc(fPZu) {" fullword ascii
    $s10 = "function jexc(Tgawz) {" fullword ascii
    $s11 = "Xfj = P; break; " fullword ascii
    $s12 = "return BGGSH;" fullword ascii
    $s13 = "function gPgc(rkQHY) {" fullword ascii
    $s14 = "function EAHgwrzm() {" fullword ascii
    $s15 = "function hiFz(nGdZP) {" fullword ascii
    $s16 = "function lhmF(bvjOc) {" fullword ascii
    $s17 = "function eegyPXl(qpWJ) {" fullword ascii
    $s18 = "if(P>=N.length) {break;}" fullword ascii
    $s19 = "function QoWp(mNnIT,qqauT) {" fullword ascii
    $s20 = "function vKhe(sbKwi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}