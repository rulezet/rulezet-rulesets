rule sig_20160411_4b0ca860169304648ccdb358e2c0bb2a {
  meta:
    description = "datamaliciousorder - file 20160411_4b0ca860169304648ccdb358e2c0bb2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e2c9729276c7af1dd4bdf3dae1d45c9e645cb346fae92062293e4168b84cf4"

  strings:
    $s1  = "function rCIRc(KLFhiR) {" fullword ascii
    $s2  = "return JuArTgN[0] + JuArTgN[2] + JuArTgN[4] + \".F\" + JuArTgN[7] + JuArTgN[9] + JuArTgN[12] + JuArTgN[14];" fullword ascii
    $s3  = "var gf = true  , aKZA = UZQ[7] + UZQ[9] + UZQ[11];" fullword ascii
    $s4  = "UlcV.open(rAtzd,slXdx,false);" fullword ascii
    $s5  = "var UZQ = (\"2.XMLHTTP FuuXkCo bwkHB XML ream St KbKHXSra AD nixvftF O lTEz D\").split(\" \");" fullword ascii
    $s6  = "function jMuhZ(PUe,qVJZR) {" fullword ascii
    $s7  = "function JtpC(XkOLp) {" fullword ascii
    $s8  = "if (ZKXRq > 158636-212){return true;} else {return false;}" fullword ascii
    $s9  = "function EAwzVXQcs(tYfNUgdoipe) {" fullword ascii
    $s10 = "function jQkA(HbVAv) {" fullword ascii
    $s11 = "function KrRVkCqQJ(iGGJi) {" fullword ascii
    $s12 = "return hQVZW;" fullword ascii
    $s13 = "function HsLF(baqBF) {" fullword ascii
    $s14 = "return cjzbRTG[0];" fullword ascii
    $s15 = "function AGBhKShS(RLD) {" fullword ascii
    $s16 = "if (vGZrm == 816-616){return true;} else {return false;}" fullword ascii
    $s17 = "function EcGm(ZKXRq) {" fullword ascii
    $s18 = "function AIWn(vGZrm) {" fullword ascii
    $s19 = "function dBlvdU(nDdh,Yndphb) {" fullword ascii
    $s20 = "function xQHwv(BBFldlEy,qQZv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}