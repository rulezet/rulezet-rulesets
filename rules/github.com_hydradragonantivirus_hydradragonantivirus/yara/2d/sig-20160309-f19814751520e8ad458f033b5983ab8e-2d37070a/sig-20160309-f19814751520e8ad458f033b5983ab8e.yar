rule sig_20160309_f19814751520e8ad458f033b5983ab8e {
  meta:
    description = "datamaliciousorder - file 20160309_f19814751520e8ad458f033b5983ab8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8beb4e9b02a7e6af116f2b5a1bbe0488348bbc3e343a58ccd78a8c8a85d6f90b"

  strings:
    $s1  = "var ES = true  , wBAR = EvD[7] + EvD[9] + EvD[11];" fullword ascii
    $s2  = "return KtYIJVn[0] + KtYIJVn[2] + KtYIJVn[4] + \".F\" + KtYIJVn[7] + KtYIJVn[9] + KtYIJVn[12] + KtYIJVn[14];" fullword ascii
    $s3  = "FixHI.open(YKTnV,KWbBF,false);" fullword ascii
    $s4  = "var KtYIJVn = \"Sc mjNgydf r jQrFrYJRP ipting warDLzI bWG ile vBZfRjDFojZIYX System mz AqgQD Obj jTUaLt ect yZzVdyY\".split(\" " ascii
    $s5  = "var EvD = (\"2.XMLHTTP MBeOPDd Egtmx XML ream St YVeqGyXh AD efPWQhY O suWU D\").split(\" \");" fullword ascii
    $s6  = "function NmGZakv(gBsf) {" fullword ascii
    $s7  = "function vizq(HWxDl) {" fullword ascii
    $s8  = "function NYWX(pdMUk) {" fullword ascii
    $s9  = "if (tbsht > 160508-160){return true;} else {return false;}" fullword ascii
    $s10 = "function XASDoGkV(tRo) {" fullword ascii
    $s11 = "function UTHR(pRLYU,HXqWL) {" fullword ascii
    $s12 = "if (AODhK == 828-628){return true;} else {return false;}" fullword ascii
    $s13 = "return qrhuZuH" fullword ascii
    $s14 = "function iZVC(RUcGi) {" fullword ascii
    $s15 = "if (y >= pdMUk.length) {break;}" fullword ascii
    $s16 = "function EYAFmKcTp(fzuyJ,JqJVh,uWuAh,yPkw) {" fullword ascii
    $s17 = "BGU = D; break; " fullword ascii
    $s18 = "function nxJdODpy(ETVmb,qZmoHj) {" fullword ascii
    $s19 = "function KWoi(AODhK) {" fullword ascii
    $s20 = "function WwsLB(TiGfeg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}