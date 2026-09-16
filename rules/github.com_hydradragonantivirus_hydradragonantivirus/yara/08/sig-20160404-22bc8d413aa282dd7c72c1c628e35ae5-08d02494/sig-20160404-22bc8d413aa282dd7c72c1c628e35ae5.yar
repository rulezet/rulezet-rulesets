rule sig_20160404_22bc8d413aa282dd7c72c1c628e35ae5 {
  meta:
    description = "datamaliciousorder - file 20160404_22bc8d413aa282dd7c72c1c628e35ae5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8428da476570f41b901db471f5e540abccfd75bdeffafabdfa811df85dba2d70"

  strings:
    $s1  = "var Db = true  , vKzN = kkC[7] + kkC[9] + kkC[11];" fullword ascii
    $s2  = "return tbfWbCB[0] + tbfWbCB[2] + tbfWbCB[4] + \".F\" + tbfWbCB[7] + tbfWbCB[9] + tbfWbCB[12] + tbfWbCB[14];" fullword ascii
    $s3  = "var tbfWbCB = pABhC(wZNSFYtcMf+\" \"+\"System Hk AYZPr Obj zovgcp ect yPTrTUT hiTvD\", \" \");" fullword ascii
    $s4  = "SzIP.open(nMcoe,vryvh,false);" fullword ascii
    $s5  = "if (jCgPB == 569-369){return true;} else {return false;}" fullword ascii
    $s6  = "function Igsy(qPYMR) {" fullword ascii
    $s7  = "ppP = L; break; " fullword ascii
    $s8  = "var lfqSWiH = \"QDlcDB*Gkq*pt.S\"+\"hell*LIORWVK*Scri*\";" fullword ascii
    $s9  = "function rvoOb(lYbDxOOo,sMoq) {" fullword ascii
    $s10 = "function HQrUTNK(fTfW,Tkttp) {" fullword ascii
    $s11 = "return \"JuHSxwrRTkAycR\";" fullword ascii
    $s12 = "function pzRxP(MsCtNq) {" fullword ascii
    $s13 = "return wgH.size;" fullword ascii
    $s14 = "function olzXE(OibmLP) {" fullword ascii
    $s15 = "if (S >= kdNBR.length) {break;}" fullword ascii
    $s16 = "return iHWZ;" fullword ascii
    $s17 = "function rMYM(rKXYO,iVfcV) {" fullword ascii
    $s18 = "function nUqQlepLv(XsHZW) {" fullword ascii
    $s19 = "return Xty.split(RXlkE);" fullword ascii
    $s20 = "function jUfu(BJEkK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}