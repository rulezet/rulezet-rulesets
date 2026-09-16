rule sig_20160314_8db43e13506612ef39bb38eda6901d47 {
  meta:
    description = "datamaliciousorder - file 20160314_8db43e13506612ef39bb38eda6901d47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84cd8d86b55aad8e29d2e2026a7cc9b2796a8a02e492431b197e29cbd86da54e"

  strings:
    $s1  = "var EG = true  , aUSq = ZoN[7] + ZoN[9] + ZoN[11];" fullword ascii
    $s2  = "return AssnHYI[0] + AssnHYI[2] + AssnHYI[4] + \".F\" + AssnHYI[7] + AssnHYI[9] + AssnHYI[12] + AssnHYI[14];" fullword ascii
    $s3  = "var ZoN = (\"2.XMLHTTP OzgonMT APhNy XML ream St BMBKOrdV AD ZEeVqql O uogy D\").split(\" \");" fullword ascii
    $s4  = "var AssnHYI = \"Sc vlhxCVp r SbffaruAE ipting ABRpFBd Bho ile QqUmFIzZedLkEa System lK CGGxA Obj gyFXgd ect hKLXMxb IvKAI\".spli" ascii
    $s5  = "sgmXZ.open(FHnwO,apWwF,false);" fullword ascii
    $s6  = "var AssnHYI = \"Sc vlhxCVp r SbffaruAE ipting ABRpFBd Bho ile QqUmFIzZedLkEa System lK CGGxA Obj gyFXgd ect hKLXMxb IvKAI\".spli" ascii
    $s7  = "return rhMbYb.position=645-645;" fullword ascii
    $s8  = "return oZUsS;" fullword ascii
    $s9  = "return zlZFq.status;" fullword ascii
    $s10 = "function GmkK(SIsOS) {" fullword ascii
    $s11 = "return frlJPNY" fullword ascii
    $s12 = "function JkXqnYUwH() {" fullword ascii
    $s13 = "function YmsVfEzTK(NPVQguccwzp) {" fullword ascii
    $s14 = "function SacH(GEkFN) {" fullword ascii
    $s15 = "function FlDtCfnI() {" fullword ascii
    $s16 = "function RRFJSdU(Jkqu) {" fullword ascii
    $s17 = "function FtDG(zlZFq) {" fullword ascii
    $s18 = "function hBSB(UmKPz,KdTEJ) {" fullword ascii
    $s19 = "return azH.size;" fullword ascii
    $s20 = "function YJgDM(FODWtg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}