rule sig_20160405_f44a64c2b2b5b5113bdce552222ae2d2 {
  meta:
    description = "datamaliciousorder - file 20160405_f44a64c2b2b5b5113bdce552222ae2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09369eb56bd9482a0b87550460d9652295e96c0eac86da6c103eb94cf4ac9163"

  strings:
    $s1  = "return jBHrosl[0] + jBHrosl[2] + jBHrosl[4] + \".F\" + jBHrosl[7] + jBHrosl[9] + jBHrosl[12] + jBHrosl[14];" fullword ascii
    $s2  = "var wO = true  , HDdT = dDd[7] + dDd[9] + dDd[11];" fullword ascii
    $s3  = "var dDd = (\"2.XMLHTTP eFJsGyi vctfR XML ream St ZIvcIYRP AD bmDpAol O Swkc D\").split(\" \");" fullword ascii
    $s4  = "tLhJ.open(xascP,HQIGY,false);" fullword ascii
    $s5  = "if (CPaAh > 166579-523){return true;} else {return false;}" fullword ascii
    $s6  = "function vtTE(aoIMg) {" fullword ascii
    $s7  = "function fkHDuy(arxxbZw) {" fullword ascii
    $s8  = "function rQZh(GIXfp,ewcgm) {" fullword ascii
    $s9  = "function yYly(CPaAh) {" fullword ascii
    $s10 = "return inWXHal;" fullword ascii
    $s11 = "function pBdp(CsdOL) {" fullword ascii
    $s12 = "function FgYvmIhwZ(RJLrC) {" fullword ascii
    $s13 = "if(P>=w.length) {break;}" fullword ascii
    $s14 = "return eCbdP;" fullword ascii
    $s15 = "function bxatA(rQExDfpE,QaRK) {" fullword ascii
    $s16 = "return CsdOL.status;" fullword ascii
    $s17 = "if (X >= Ntgcs.length) {break;}" fullword ascii
    $s18 = "function FochW(RlP,vnaBu) {" fullword ascii
    $s19 = "return hYb.size;" fullword ascii
    $s20 = "function PMSm(Ntgcs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}