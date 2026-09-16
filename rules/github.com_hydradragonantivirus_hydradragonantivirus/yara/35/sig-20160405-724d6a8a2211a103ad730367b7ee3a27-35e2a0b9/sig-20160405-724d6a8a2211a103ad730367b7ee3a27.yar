rule sig_20160405_724d6a8a2211a103ad730367b7ee3a27 {
  meta:
    description = "datamaliciousorder - file 20160405_724d6a8a2211a103ad730367b7ee3a27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9ad2081e0e6c731596e94213988b576c47c4f62774dfed27f88b2249b94523"

  strings:
    $s1  = "return FkATLak[0] + FkATLak[2] + FkATLak[4] + \".F\" + FkATLak[7] + FkATLak[9] + FkATLak[12] + FkATLak[14];" fullword ascii
    $s2  = "var wC = true  , HqRI = RZN[7] + RZN[9] + RZN[11];" fullword ascii
    $s3  = "pnzq.open(yUPoJ,AanOi,false);" fullword ascii
    $s4  = "var RZN = (\"2.XMLHTTP pyOtCcI xAFuM XML ream St UeAkiTpV AD ilJEcFq O HThr D\").split(\" \");" fullword ascii
    $s5  = "if(P>=N.length) {break;}" fullword ascii
    $s6  = "function mqwV(ZNtSX) {" fullword ascii
    $s7  = "if (vGIxb == 817-617){return true;} else {return false;}" fullword ascii
    $s8  = "return TLAepTT[0];" fullword ascii
    $s9  = "function efPI(weqfD) {" fullword ascii
    $s10 = "function AVQQd(PWH,htlpa) {" fullword ascii
    $s11 = "function ScsN(VUKbe,AanOi,yUPoJ) {" fullword ascii
    $s12 = "function ZYyknOk(CNAg) {" fullword ascii
    $s13 = "function wvuDzLIHP(McZuv) {" fullword ascii
    $s14 = "function LuPfX(GdxcJlMP,uTrC) {" fullword ascii
    $s15 = "return yHzbozM(lo,imymB[1001-995]+imymB[245-238]+imymB[129-121]);" fullword ascii
    $s16 = "function cZYv(PipFH) {" fullword ascii
    $s17 = "return new ActiveXObject(Avjl);" fullword ascii
    $s18 = "function FqmQqesSU(uKWPReiBaZR) {" fullword ascii
    $s19 = "function AMFf(MGFao,esqZb) {" fullword ascii
    $s20 = "function vSuXSvEp(HhKX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}