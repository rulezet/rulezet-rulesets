rule sig_20160310_25bdb86fbb85b7cf08215fd3275164d6 {
  meta:
    description = "datamaliciousorder - file 20160310_25bdb86fbb85b7cf08215fd3275164d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ee68a84646dcff49a7498a1c40c4e651e0c60f8a6c2d835d2723c9ab4fa3b11"

  strings:
    $s1  = "var nPZcI = \"qIxBKv KPz pt.Shell vmtFsxB Scri Clee %TE MP% \\\\ SNlwsyvwl\".split(\" \");" fullword ascii
    $s2  = "var Th = true  , IanT = NJS[7] + NJS[9] + NJS[11];" fullword ascii
    $s3  = "return MiudcjD[0] + MiudcjD[2] + MiudcjD[4] + \".F\" + MiudcjD[7] + MiudcjD[9] + MiudcjD[12] + MiudcjD[14];" fullword ascii
    $s4  = "var NJS = (\"2.XMLHTTP JshmxdQ AUXZm XML ream St YYKXDTmS AD GLgORdi O jByI D\").split(\" \");" fullword ascii
    $s5  = "bOyIA.open(LKvVZ,IFQHx,false);" fullword ascii
    $s6  = "return QnVUL.status;" fullword ascii
    $s7  = "function ZNRV(HopyH,CWTXW) {" fullword ascii
    $s8  = "function oieS(syxsn) {" fullword ascii
    $s9  = "function RulGJDalY(bTMXGoSnLzM) {" fullword ascii
    $s10 = "function FHnXsZkR() {" fullword ascii
    $s11 = "if (KHhTM > 150500-236){return true;} else {return false;}" fullword ascii
    $s12 = "function PgDCDyWvD(zASOY,mqIWF,EDuzv,PEDm) {" fullword ascii
    $s13 = "function rlod(jFYJA) {" fullword ascii
    $s14 = "if (y >= syxsn.length) {break;}" fullword ascii
    $s15 = "return ZiLYN;" fullword ascii
    $s16 = "function BMbVZ(WdGaKS) {" fullword ascii
    $s17 = "function VeFxH(xvuMLl) {" fullword ascii
    $s18 = "return new ActiveXObject(xvuMLl);" fullword ascii
    $s19 = "function WpEyhIIi(AuTCg,zQYsxK) {" fullword ascii
    $s20 = "function rKTK(kpVCc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}