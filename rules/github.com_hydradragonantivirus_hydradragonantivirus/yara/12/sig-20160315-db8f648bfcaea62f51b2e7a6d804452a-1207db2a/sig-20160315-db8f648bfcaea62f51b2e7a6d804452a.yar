rule sig_20160315_db8f648bfcaea62f51b2e7a6d804452a {
  meta:
    description = "datamaliciousorder - file 20160315_db8f648bfcaea62f51b2e7a6d804452a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53ea300b1e441cab6502dd789775ae55c6c1f6fe8f3e71a38db0da8399a2c58b"

  strings:
    $s1  = "return aeXhswi[0] + aeXhswi[2] + aeXhswi[4] + \".F\" + aeXhswi[7] + aeXhswi[9] + aeXhswi[12] + aeXhswi[14];" fullword ascii
    $s2  = "var Oa = true  , pWWr = JyJ[7] + JyJ[9] + JyJ[11];" fullword ascii
    $s3  = "var JyJ = (\"2.XMLHTTP LhJPjMQ qZVyA XML ream St xqOCmnfJ AD JJzREkB O vEGV D\").split(\" \");" fullword ascii
    $s4  = "pcTIi.open(VMRXr,HhECY,false);" fullword ascii
    $s5  = "function ZyqJF(XRo,vMcyS) {" fullword ascii
    $s6  = "function rmKgKWjN(teQ) {" fullword ascii
    $s7  = "function YyHu(RsfJG) {" fullword ascii
    $s8  = "return XRo.split(vMcyS);" fullword ascii
    $s9  = "function jspg(pBPQz) {" fullword ascii
    $s10 = "function AfmQ(dbKuL) {" fullword ascii
    $s11 = "return pDUH.responseBody;" fullword ascii
    $s12 = "return teQ.size;" fullword ascii
    $s13 = "return ttuYGWD" fullword ascii
    $s14 = "function hKEsp(yWVqFB) {" fullword ascii
    $s15 = "function oZyQ(aRuoq) {" fullword ascii
    $s16 = "function soiD(JzErN,uFIhl) {" fullword ascii
    $s17 = "return kVrYu.status;" fullword ascii
    $s18 = "if (RsfJG > 195800-750){return true;} else {return false;}" fullword ascii
    $s19 = "function fzqwtgdfy(gZkJE) {" fullword ascii
    $s20 = "function SPSnflUA() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}