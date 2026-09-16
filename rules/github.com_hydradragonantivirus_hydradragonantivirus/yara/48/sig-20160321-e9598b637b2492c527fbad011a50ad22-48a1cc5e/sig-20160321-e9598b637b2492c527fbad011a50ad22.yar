rule sig_20160321_e9598b637b2492c527fbad011a50ad22 {
  meta:
    description = "datamaliciousorder - file 20160321_e9598b637b2492c527fbad011a50ad22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2437a1985cecf7414a93db6da322d9f9d22a896dcb0fcf40bd1166d86b0a514f"

  strings:
    $s1  = "return WScript.CreateObject(seUeE);" fullword ascii
    $s2  = "return PREQeWi[0] + PREQeWi[2] + PREQeWi[4] + \".F\" + PREQeWi[7] + PREQeWi[9] + PREQeWi[12] + PREQeWi[14];" fullword ascii
    $s3  = "var XD = true  , jzXG = Mlj[7] + Mlj[9] + Mlj[11];" fullword ascii
    $s4  = "ocReW.open(XqMcz,MEfbY,false);" fullword ascii
    $s5  = "var Mlj = (\"2.XMLHTTP CNdbfNh BLyMA XML ream St BleyARam AD brtbBRr O uLmw D\").split(\" \");" fullword ascii
    $s6  = "return SMmRo.status;" fullword ascii
    $s7  = "function RIIAdzwU(eQkt) {" fullword ascii
    $s8  = "function hQms(jAEiM) {" fullword ascii
    $s9  = "function ArPD(ocReW,MEfbY,XqMcz) {" fullword ascii
    $s10 = "return ELpCza.position=232-232;" fullword ascii
    $s11 = "function kqIX(tVtBQ) {" fullword ascii
    $s12 = "if (rkXtx > 171472-724){return true;} else {return false;}" fullword ascii
    $s13 = "return nPUcXND(UP,zExfG[383-377]+zExfG[897-890]+zExfG[349-341]);" fullword ascii
    $s14 = "return new ActiveXObject(zBWHZr);" fullword ascii
    $s15 = "function AXcb(gEIEC) {" fullword ascii
    $s16 = "if (I >= tVtBQ.length) {break;}" fullword ascii
    $s17 = "function RAVa(seUeE) {" fullword ascii
    $s18 = "return nhB.split(bXfUh);" fullword ascii
    $s19 = "function TTBRNYuDz(KODTvTDPZGS) {" fullword ascii
    $s20 = "function uGGc(ARBsR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}