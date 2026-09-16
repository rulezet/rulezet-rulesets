rule sig_20160324_77bce4be4ef57d18a2d3d6281b849d1a {
  meta:
    description = "datamaliciousorder - file 20160324_77bce4be4ef57d18a2d3d6281b849d1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b11b9c6a2093c874311892db651ba58d78e1bc44d504e0c77fe1101672acbf7d"

  strings:
    $s1  = "return WScript.CreateObject(wtaOP);" fullword ascii
    $s2  = "var XI = true  , fnhQ = rVd[7] + rVd[9] + rVd[11];" fullword ascii
    $s3  = "return LjZiMBU[0] + LjZiMBU[2] + LjZiMBU[4] + \".F\" + LjZiMBU[7] + LjZiMBU[9] + LjZiMBU[12] + LjZiMBU[14];" fullword ascii
    $s4  = "return SGmSnk/*tElRBINHIzdE0oqPLTSLRSPe3*/.position=701-701;" fullword ascii
    $s5  = "QhQq.open(Hwikr,PDuuV,false);" fullword ascii
    $s6  = "var LjZiMBU = hWpCy(GDLvXTcHfP+\" \"+\"System LP Gddyu Obj IZIJMs ect pYJkrhM BbIIl\", \" \");" fullword ascii
    $s7  = "var rVd = (\"2.XMLHTTP XTRPjzP EmzQW XML ream St AJZsNusl AD KEdLDBP O tuXo D\").split(\" \");" fullword ascii
    $s8  = "if(d>=F.length) {break;}" fullword ascii
    $s9  = "function UfCIu(wPqwmk) {" fullword ascii
    $s10 = "function crjBqNTRD(SdTvJ) {" fullword ascii
    $s11 = "return LkoYa;" fullword ascii
    $s12 = "return mra.split(IIKqe);" fullword ascii
    $s13 = "if (hRICU == 839-639){return true;} else {return false;}" fullword ascii
    $s14 = "function bbdW(HwrjL) {" fullword ascii
    $s15 = "return XpWeINJ(aj,iWYnH[187-181]+iWYnH[704-697]+iWYnH[223-215]);" fullword ascii
    $s16 = "function SbfdoXV(YQQU) {" fullword ascii
    $s17 = "if (USfOx > 165398-956){return true;} else {return false;}" fullword ascii
    $s18 = "function KSmK(wtaOP) {" fullword ascii
    $s19 = "function RbjnP(ktMrgBMU,rTEj) {" fullword ascii
    $s20 = "function fyUT(sLxOH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}