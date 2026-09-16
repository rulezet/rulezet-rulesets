rule sig_20160309_8e0a908aa670c1735ddc12e81e57f762 {
  meta:
    description = "datamaliciousorder - file 20160309_8e0a908aa670c1735ddc12e81e57f762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6428c31f2b1de8ffc09fe754310db9d443dfdf9365029f60b3e6fb42ffe3de"

  strings:
    $s1  = "return BDBjunT[0] + BDBjunT[2] + BDBjunT[4] + \".F\" + BDBjunT[7] + BDBjunT[9] + BDBjunT[12] + BDBjunT[14];" fullword ascii
    $s2  = "var gA = true  , Zlfq = XHr[7] + XHr[9] + XHr[11];" fullword ascii
    $s3  = "var XHr = (\"2.XMLHTTP TCvjgdX Qazqk XML ream St iAhVhvpG AD xDzYilp O rOtm D\").split(\" \");" fullword ascii
    $s4  = "uGqSO.open(pVbwt,vNsak,false);" fullword ascii
    $s5  = "var BDBjunT = \"Sc tmyDsXq r SBOBDNedF ipting krQzyLm RhD ile OTEwsxMsTicCoi System qL HRvvu Obj zIBOXb ect vKfGMrB\".split(\" " ascii
    $s6  = "if(C>=u.length) {break;}" fullword ascii
    $s7  = "return ScD.size;" fullword ascii
    $s8  = "return FtbFFSq" fullword ascii
    $s9  = "return oowVb;" fullword ascii
    $s10 = "function nijKDBZhb(YmLhR,KtIUt,xnwjs,tNUr) {" fullword ascii
    $s11 = "function qnxR(fACNE) {" fullword ascii
    $s12 = "function VjUSlvA(ifLv) {" fullword ascii
    $s13 = "function Wmfe(hiekv) {" fullword ascii
    $s14 = "function UgUFYoEl() {" fullword ascii
    $s15 = "function ddwD(bOxkG) {" fullword ascii
    $s16 = "function cgus(SMiCc,gcUXc) {" fullword ascii
    $s17 = "function TNVdU(tleZUx) {" fullword ascii
    $s18 = "if (kqNVd == 805-605){return true;} else {return false;}" fullword ascii
    $s19 = "return wdIL.ExpandEnvironmentStrings(tBtiG);" fullword ascii
    $s20 = "function lsXKYHA(wdIL,tBtiG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}