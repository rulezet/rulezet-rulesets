rule sig_20160411_d20a9d43bac2859f9fd9e0f566e6ed46 {
  meta:
    description = "datamaliciousorder - file 20160411_d20a9d43bac2859f9fd9e0f566e6ed46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3a41302ff77eeb1d3822412659c922a7d925fc002f65102f7e3cbe1e0d97278"

  strings:
    $s1  = "function TsDllxyAg(ymYLJ) {" fullword ascii
    $s2  = "var Rf = true  , fGyl = gDT[7] + gDT[9] + gDT[11];" fullword ascii
    $s3  = "return rwKhRNa[0] + rwKhRNa[2] + rwKhRNa[4] + \".F\" + rwKhRNa[7] + rwKhRNa[9] + rwKhRNa[12] + rwKhRNa[14];" fullword ascii
    $s4  = "zaOx.open(OBtNZ,KEMWw,false);" fullword ascii
    $s5  = "var gDT = (\"2.XMLHTTP vLbbXMj BsqRj XML ream St rgcczXnF AD qHsKvQS O bprk D\").split(\" \");" fullword ascii
    $s6  = "function xraVx(Cfn,RiVjd) {" fullword ascii
    $s7  = "function HcXQdz(YgHm,gKkSjm) {" fullword ascii
    $s8  = "return Cfn[eqNw[0]](RiVjd);" fullword ascii
    $s9  = "function DPBsImGGe(duShZsPHYVX) {" fullword ascii
    $s10 = "function mVRpB(rWeyxA) {" fullword ascii
    $s11 = "function eiAo(DMdbv,Cowbf) {" fullword ascii
    $s12 = "function lfImNqt(fbPW) {" fullword ascii
    $s13 = "return yFcvO;" fullword ascii
    $s14 = "function bgxpI(bptgJf) {" fullword ascii
    $s15 = "function coxxsXCh(TCu) {" fullword ascii
    $s16 = "function vTwMZkc(HkAU,uyMDt) {" fullword ascii
    $s17 = "if (rQBuD == 576-376){return true;} else {return false;}" fullword ascii
    $s18 = "function dpsj(rQBuD) {" fullword ascii
    $s19 = "return aujbnIz[0];" fullword ascii
    $s20 = "return vTwMZkc(YZ,QyRDLu+bFaBQ[564-556]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}