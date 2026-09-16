rule sig_20160310_49bc558d22f48680066aa68982de7079 {
  meta:
    description = "datamaliciousorder - file 20160310_49bc558d22f48680066aa68982de7079.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8342af2b165405e1c009d8167cc62178fa98b36e125f6e76f3447c9c4ce38dfd"

  strings:
    $s1  = "return usFbeLJ[0] + usFbeLJ[2] + usFbeLJ[4] + \".F\" + usFbeLJ[7] + usFbeLJ[9] + usFbeLJ[12] + usFbeLJ[14];" fullword ascii
    $s2  = "var fU = true  , Txic = fFK[7] + fFK[9] + fFK[11];" fullword ascii
    $s3  = "gquqm.open(ksMbn,sfEsM,false);" fullword ascii
    $s4  = "var fFK = (\"2.XMLHTTP ngnULcm VnIad XML ream St DEeeBDCp AD FBnDDuu O zJIN D\").split(\" \");" fullword ascii
    $s5  = "return FxqUWVW(yW,DibMm[432-426]+DibMm[426-419]+DibMm[995-987]);" fullword ascii
    $s6  = "function ChyL(gquqm,sfEsM,ksMbn) {" fullword ascii
    $s7  = "function gpRZKmAQU(bfhus,uOcHj,EPQEW,dHRj) {" fullword ascii
    $s8  = "return SVNFb;" fullword ascii
    $s9  = "function FxqUWVW(XnZf,pqooA) {" fullword ascii
    $s10 = "function GhBY(kqyhx) {" fullword ascii
    $s11 = "function vQqr(cQHPe,KTqlT) {" fullword ascii
    $s12 = "function RTjAa(EnBMZm) {" fullword ascii
    $s13 = "return xsx.size;" fullword ascii
    $s14 = "return HkWoR.status;" fullword ascii
    $s15 = "return lSOq.responseBody;" fullword ascii
    $s16 = "function uiuad(dwprrC) {" fullword ascii
    $s17 = "function xBswHUqh(YIELp,OHJEHz) {" fullword ascii
    $s18 = "function uNyT(zkOon) {" fullword ascii
    $s19 = "if (nvglJ == 1072-872){return true;} else {return false;}" fullword ascii
    $s20 = "return EnBMZm.position=834-834;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}