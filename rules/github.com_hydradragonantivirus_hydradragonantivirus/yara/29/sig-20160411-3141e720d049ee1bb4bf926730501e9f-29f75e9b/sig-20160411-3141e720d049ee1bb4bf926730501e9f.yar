rule sig_20160411_3141e720d049ee1bb4bf926730501e9f {
  meta:
    description = "datamaliciousorder - file 20160411_3141e720d049ee1bb4bf926730501e9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f726f7f005d8fcdb6c202a050dd657b26a6d8212d2e51626311ff7469efea72f"

  strings:
    $s1  = "var ai = true  , vZta = jKR[7] + jKR[9] + jKR[11];" fullword ascii
    $s2  = "return pwHbOay[0] + pwHbOay[2] + pwHbOay[4] + \".F\" + pwHbOay[7] + pwHbOay[9] + pwHbOay[12] + pwHbOay[14];" fullword ascii
    $s3  = "var jKR = (\"2.XMLHTTP FUsqfwK txSDY XML ream St VHmZJPyh AD CLlVkPH O JGKb D\").split(\" \");" fullword ascii
    $s4  = "mwWi.open(uvIpA,VFRyh,false);" fullword ascii
    $s5  = "function uUrn(gXGtb,uvkBj) {" fullword ascii
    $s6  = "function WZpW(Tvtnv) {" fullword ascii
    $s7  = "return kGqyxWs[0];" fullword ascii
    $s8  = "return yMi[iYEl[0]](WUNXh);" fullword ascii
    $s9  = "function srcp(ynEDd) {" fullword ascii
    $s10 = "function ejKEjyBJE(trwFU) {" fullword ascii
    $s11 = "function BBlH(GkyPJ,VFRyh,uvIpA) {" fullword ascii
    $s12 = "if (h >= Tvtnv.length) {break;}" fullword ascii
    $s13 = "function GQsZn(LAnoZl) {" fullword ascii
    $s14 = "return ActENgk;" fullword ascii
    $s15 = "lLE = b; break; " fullword ascii
    $s16 = "function JpJMIYrB(ngaG) {" fullword ascii
    $s17 = "function LBAwtgy(aPpI) {" fullword ascii
    $s18 = "return DxBoOqt(ug,uqBmMM+GtURF[557-549]);" fullword ascii
    $s19 = "return \"TwqQfJHosldGSo\";" fullword ascii
    $s20 = "if (gImNs > 186890-456){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}