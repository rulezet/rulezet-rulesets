rule sig_20160404_4fdb0991739b5f92a1e0cfeaede33887 {
  meta:
    description = "datamaliciousorder - file 20160404_4fdb0991739b5f92a1e0cfeaede33887.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31f67aef1dedc575a9f2031e1ad0171cfb30caa21a9138d96775564892a7b3bd"

  strings:
    $s1  = "return SuvdJqP[0] + SuvdJqP[2] + SuvdJqP[4] + \".F\" + SuvdJqP[7] + SuvdJqP[9] + SuvdJqP[12] + SuvdJqP[14];" fullword ascii
    $s2  = "var Nz = true  , nxIi = YVs[7] + YVs[9] + YVs[11];" fullword ascii
    $s3  = "CCgP.open(udLfF,dCJam,false);" fullword ascii
    $s4  = "var SuvdJqP = lPVCR(qdPnsLpsAn+\" \"+\"System Uk CYNnJ Obj TUBrKd ect FHdtXyd EyPjH\", \" \");" fullword ascii
    $s5  = "var YVs = (\"2.XMLHTTP qxCuvAI yYlRD XML ream St srbwaROP AD qjnGhpP O Fgps D\").split(\" \");" fullword ascii
    $s6  = "var Pk = NoSe(Rk).split(\" \");" fullword ascii
    $s7  = "return COjJx;" fullword ascii
    $s8  = "function YStqjpUw(kwtg) {" fullword ascii
    $s9  = "return GkN.split(whZFz);" fullword ascii
    $s10 = "function URtG(fZIYS) {" fullword ascii
    $s11 = "function lPVCR(GkN,whZFz) {" fullword ascii
    $s12 = "function nrDfSSzRY(MkpLw) {" fullword ascii
    $s13 = "if (gSsUk > 160721-822){return true;} else {return false;}" fullword ascii
    $s14 = "function okKs(rGzZN,jQHfM) {" fullword ascii
    $s15 = "return \"FxOFRqdLUYplIt\";" fullword ascii
    $s16 = "function aoSK(HwIuL) {" fullword ascii
    $s17 = "function BiQQj(LNCkClBR,xGrS) {" fullword ascii
    $s18 = "function RQlaMIh(NMPU) {" fullword ascii
    $s19 = "return NMPU[HcQqGV[0]];" fullword ascii
    $s20 = "if (fZIYS == 509-309){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}