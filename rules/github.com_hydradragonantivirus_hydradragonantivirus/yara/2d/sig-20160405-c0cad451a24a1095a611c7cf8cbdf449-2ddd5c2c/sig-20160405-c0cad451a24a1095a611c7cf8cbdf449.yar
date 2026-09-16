rule sig_20160405_c0cad451a24a1095a611c7cf8cbdf449 {
  meta:
    description = "datamaliciousorder - file 20160405_c0cad451a24a1095a611c7cf8cbdf449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6a713a3dece3dc2bb8b540da516a367a12dc59d54b225e1214456ddac63f74"

  strings:
    $s1  = "return cLZxqEO[0] + cLZxqEO[2] + cLZxqEO[4] + \".F\" + cLZxqEO[7] + cLZxqEO[9] + cLZxqEO[12] + cLZxqEO[14];" fullword ascii
    $s2  = "var Jc = true  , ylXj = BYX[7] + BYX[9] + BYX[11];" fullword ascii
    $s3  = "ksLk.open(BuRPu,ZIanG,false);" fullword ascii
    $s4  = "var BYX = (\"2.XMLHTTP enJfPfx zcpFK XML ream St vIjeBwuO AD wWMMpTR O WjMT D\").split(\" \");" fullword ascii
    $s5  = "if(V>=X.length) {break;}" fullword ascii
    $s6  = "return wUb.size;" fullword ascii
    $s7  = "return Bkmzv.status;" fullword ascii
    $s8  = "function IsCMJiz(PQgh,GLhwc) {" fullword ascii
    $s9  = "function lduF(Bkmzv) {" fullword ascii
    $s10 = "function IuVej(WpLzYp) {" fullword ascii
    $s11 = "function olCr(Bqlgm,hLxxs) {" fullword ascii
    $s12 = "return new ActiveXObject(cHtd);" fullword ascii
    $s13 = "function fnNo(jmeRV) {" fullword ascii
    $s14 = "if (jmeRV == 1131-931){return true;} else {return false;}" fullword ascii
    $s15 = "function sNGx(oHsfY) {" fullword ascii
    $s16 = "function Eimzniepz(yvLuJ) {" fullword ascii
    $s17 = "return \"UZLtCNGUfmxBXh\";" fullword ascii
    $s18 = "function XDYC(AHqoh,ZIanG,BuRPu) {" fullword ascii
    $s19 = "return hqTrhMu;" fullword ascii
    $s20 = "return GcNx[XaZKFf[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}