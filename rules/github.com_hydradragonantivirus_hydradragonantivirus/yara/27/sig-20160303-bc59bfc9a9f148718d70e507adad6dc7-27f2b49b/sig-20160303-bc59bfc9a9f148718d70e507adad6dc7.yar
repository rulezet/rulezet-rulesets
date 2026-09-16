rule sig_20160303_bc59bfc9a9f148718d70e507adad6dc7 {
  meta:
    description = "datamaliciousorder - file 20160303_bc59bfc9a9f148718d70e507adad6dc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7c2cfe24d8c60b43444445cad86fe33e7c0dbb75c1b1ac4d0c346aa01b3c191"

  strings:
    $s1  = "var NlZkF = \"evZAUx Mny pt.Shell wzTwPkU Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var ZER = (lzj + \"TTP\" + \" BrEzrhm bKrOg XML ream St zyIoQXWc AD uGHplrb OD\").split(\" \");" fullword ascii
    $s3  = "var Nu = true  , hdcI = ZER[7] + \"\" + ZER[9];" fullword ascii
    $s4  = "return jCsZrUR[0] + jCsZrUR[2] + jCsZrUR[4] + \".F\" + jCsZrUR[7] + jCsZrUR[9] + jCsZrUR[12] + jCsZrUR[14];" fullword ascii
    $s5  = "tyAmH.open(pcnJk,KUfWW,false);" fullword ascii
    $s6  = "var jCsZrUR = \"Sc DEHvUGY r MiDoPvgMZ ipting BksvUHc EOL ile fDcJeNyszIeFjj System gt UOOXM Obj BgNjTX ect ymwADHE\".split(\" " ascii
    $s7  = "function vpmb(kjNlA,tHpxU) {" fullword ascii
    $s8  = "return ooTwE;" fullword ascii
    $s9  = "function EBAN(oZflC) {" fullword ascii
    $s10 = "return TuUW.responseBody;" fullword ascii
    $s11 = "function bwAU(UQMVa,mviMl) {" fullword ascii
    $s12 = "function yGjR(eFiXv) {" fullword ascii
    $s13 = "function JdBU(tyAmH,KUfWW,pcnJk) {" fullword ascii
    $s14 = "if(u>=e.length) {break;}" fullword ascii
    $s15 = "function CEhU(ECnTI) {" fullword ascii
    $s16 = "function AejGQlVe() {" fullword ascii
    $s17 = "function MpijMzL(SOgf) {" fullword ascii
    $s18 = "if (eFiXv > 158231-824){return true;} else {return false;}" fullword ascii
    $s19 = "return new ActiveXObject(PXhqNC);" fullword ascii
    $s20 = "function BnlLjjJ(TuUW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}