rule sig_20160405_fb7c096e10a912bd9daa9a5d8b256008 {
  meta:
    description = "datamaliciousorder - file 20160405_fb7c096e10a912bd9daa9a5d8b256008.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9492696fe9e542e596b1b34d5b2bcd829479182cc96171a80bd1bdd8f3abcecc"

  strings:
    $s1  = "var oV = true  , cPXs = nPq[7] + nPq[9] + nPq[11];" fullword ascii
    $s2  = "return pUqFgOy[0] + pUqFgOy[2] + pUqFgOy[4] + \".F\" + pUqFgOy[7] + pUqFgOy[9] + pUqFgOy[12] + pUqFgOy[14];" fullword ascii
    $s3  = "ISXS.open(tDNvz,DhDZD,false);" fullword ascii
    $s4  = "var nPq = (\"2.XMLHTTP nHBFWQA OuAOv XML ream St gJGuIqVr AD fUdRKeR O ePEa D\").split(\" \");" fullword ascii
    $s5  = "if(x>=b.length) {break;}" fullword ascii
    $s6  = "function bMvL(jpbuN) {" fullword ascii
    $s7  = "function IHIwczNrt(ZtFQS) {" fullword ascii
    $s8  = "function VYPc(oziIG) {" fullword ascii
    $s9  = "pRV = x; break; " fullword ascii
    $s10 = "return EtBfUwm(Kr,gcFKx[692-686]+gcFKx[203-196]+gcFKx[889-881]);" fullword ascii
    $s11 = "if (ZKfNj == 325-125){return true;} else {return false;}" fullword ascii
    $s12 = "return \"qbDxTdJqlMrZFM\";" fullword ascii
    $s13 = "function gexrvM(vYxqRnG) {" fullword ascii
    $s14 = "function hOUO(fFbCn,atOAb) {" fullword ascii
    $s15 = "function imUo(JFDMT,COhSP) {" fullword ascii
    $s16 = "function DNkUc(HShnnQ) {" fullword ascii
    $s17 = "return DSEbX.status;" fullword ascii
    $s18 = "function JEUF(ZQhJj) {" fullword ascii
    $s19 = "return ReU.size;" fullword ascii
    $s20 = "function wlIu(Waoyl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}