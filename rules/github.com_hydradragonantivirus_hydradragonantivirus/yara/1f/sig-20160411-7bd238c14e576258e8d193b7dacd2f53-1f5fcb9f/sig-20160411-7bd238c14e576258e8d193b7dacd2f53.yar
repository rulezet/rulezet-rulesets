rule sig_20160411_7bd238c14e576258e8d193b7dacd2f53 {
  meta:
    description = "datamaliciousorder - file 20160411_7bd238c14e576258e8d193b7dacd2f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecebd5aa58dcb91b40cb64ba1dd4c3f3fa6fa162c080001bb223fe6865e16f8f"

  strings:
    $s1  = "var fql = (\"2.XMLHTTP ePurWqO JDIei XML ream St IZlognkZ AD oqgnUuK O DugC D\").split(\" \");" fullword ascii
    $s2  = "return Hyaqhva[0] + Hyaqhva[2] + Hyaqhva[4] + \".F\" + Hyaqhva[7] + Hyaqhva[9] + Hyaqhva[12] + Hyaqhva[14];" fullword ascii
    $s3  = "var AY = true  , VOyK = fql[7] + fql[9] + fql[11];" fullword ascii
    $s4  = "ECRW.open(QqKsa,soSWr,false);" fullword ascii
    $s5  = "if(d>=y.length) {break;}" fullword ascii
    $s6  = "return JdMyEr[HVoQ[622-622]]=362-362;" fullword ascii
    $s7  = "function OHPa(ioXjp) {" fullword ascii
    $s8  = "function PkIzv(QjpeJn) {" fullword ascii
    $s9  = "function sWcMZqJ(zhhi,xyDmS) {" fullword ascii
    $s10 = "function oUnI(etVeA) {" fullword ascii
    $s11 = "function sEKps(slu,gdAxK) {" fullword ascii
    $s12 = "function ypId(FYTKx,zTEnf) {" fullword ascii
    $s13 = "function kkUN(GzHeo) {" fullword ascii
    $s14 = "function RMoc(AQGXc) {" fullword ascii
    $s15 = "function niey(sJXvv) {" fullword ascii
    $s16 = "return GzHeo.status;" fullword ascii
    $s17 = "function TEsRNoB(MurW) {" fullword ascii
    $s18 = "aJB = d; break; " fullword ascii
    $s19 = "function Wurwvc(AfIvvMY) {" fullword ascii
    $s20 = "return ljxCbZa;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}