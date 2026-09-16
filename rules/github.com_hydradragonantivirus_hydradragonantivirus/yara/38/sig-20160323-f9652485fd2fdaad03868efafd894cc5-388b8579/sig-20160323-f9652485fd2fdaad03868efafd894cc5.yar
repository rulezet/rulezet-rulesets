rule sig_20160323_f9652485fd2fdaad03868efafd894cc5 {
  meta:
    description = "datamaliciousorder - file 20160323_f9652485fd2fdaad03868efafd894cc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e14b85b789e19846eb4876c5721ba097f763c6bfa1d2726dc325902b35986f5c"

  strings:
    $s1  = "return WScript.CreateObject(gEokB);" fullword ascii
    $s2  = "var QcdSzAxI = agha(zPuCjJAC[527-526] + zPuCjJAC[620-617] + zPuCjJAC[870-865] + zPuCjJAC[783-777] + zPuCjJAC[928-920] + zPuCjJAC" ascii
    $s3  = "var JgP = agha(wsZW + \"B.\" + lXx[5]+(388001, lXx[4]));" fullword ascii
    $s4  = "return vYikYxD[0] + vYikYxD[2] + vYikYxD[4] + \".F\" + vYikYxD[7] + vYikYxD[9] + vYikYxD[12] + vYikYxD[14];" fullword ascii
    $s5  = "var QcdSzAxI = agha(zPuCjJAC[527-526] + zPuCjJAC[620-617] + zPuCjJAC[870-865] + zPuCjJAC[783-777] + zPuCjJAC[928-920] + zPuCjJAC" ascii
    $s6  = "var ji = true  , wsZW = lXx[7] + lXx[9] + lXx[11];" fullword ascii
    $s7  = "var lXx = (\"2.XMLHTTP VhjIsLq iiEod XML ream St fxspRTlf AD eoKbMsp O zoNE D\").split(\" \");" fullword ascii
    $s8  = "tMBw.open(cHEMq,rgSSE,false);" fullword ascii
    $s9  = "function YOdTMPBpE(WiAUk) {" fullword ascii
    $s10 = "var vYikYxD = EURPi(PhAANPdwnw+\" \"+\"System rO GhhRR Obj MtQDmH ect YwfmXrM ZzNQf\", \" \");" fullword ascii
    $s11 = "return YjV.split(ibphB);" fullword ascii
    $s12 = "if(u>=z.length) {break;}" fullword ascii
    $s13 = "if (RqPbA == 574-374){return true;} else {return false;}" fullword ascii
    $s14 = "function MRuqSIuJ(Ztmq) {" fullword ascii
    $s15 = "return TagIR;" fullword ascii
    $s16 = "if (nJrqH > 191109-611){return true;} else {return false;}" fullword ascii
    $s17 = "if (g >= BnagB.length) {break;}" fullword ascii
    $s18 = "function hxfM(LAigc) {" fullword ascii
    $s19 = "function BiPDKWc(LAFX,EsKnt) {" fullword ascii
    $s20 = "function xHuE(SrMyJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}