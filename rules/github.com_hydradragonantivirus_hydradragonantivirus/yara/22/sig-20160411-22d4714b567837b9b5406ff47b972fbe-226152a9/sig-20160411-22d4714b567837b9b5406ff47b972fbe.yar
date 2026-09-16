rule sig_20160411_22d4714b567837b9b5406ff47b972fbe {
  meta:
    description = "datamaliciousorder - file 20160411_22d4714b567837b9b5406ff47b972fbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7404e9074f3180740d735a20100243ebdac84cbe12ef47bc24f17133bb8e9143"

  strings:
    $s1  = "var TN = true  , trMR = YoU[7] + YoU[9] + YoU[11];" fullword ascii
    $s2  = "return NUuwzgi[0] + NUuwzgi[2] + NUuwzgi[4] + \".F\" + NUuwzgi[7] + NUuwzgi[9] + NUuwzgi[12] + NUuwzgi[14];" fullword ascii
    $s3  = "var YoU = (\"2.XMLHTTP bNzaekM wcFIa XML ream St WwWrEJBR AD bPTFCOa O TYnc D\").split(\" \");" fullword ascii
    $s4  = "function ckbrH(FGO,zaGtJ) {" fullword ascii
    $s5  = "return WWfoA.status;" fullword ascii
    $s6  = "return frN.size;" fullword ascii
    $s7  = "function zvJsv(VzRewM) {" fullword ascii
    $s8  = "function RmKirf(tbxpqed) {" fullword ascii
    $s9  = "function cPUX(wmTOZ,cZZlV) {" fullword ascii
    $s10 = "function CBXUdgX(MWcZ) {" fullword ascii
    $s11 = "function bqvUR(hqCbFPUT,IbtO) {" fullword ascii
    $s12 = "function dXnA(WWfoA) {" fullword ascii
    $s13 = "function BHZyjO(ylkW,iDFEmi) {" fullword ascii
    $s14 = "function xARl(kQJYM) {" fullword ascii
    $s15 = "function fbzodHEW(frN) {" fullword ascii
    $s16 = "return new ActiveXObject(jrMZ);" fullword ascii
    $s17 = "function HreX(JawIa) {" fullword ascii
    $s18 = "function bEsW(CpZti) {" fullword ascii
    $s19 = "function DwQF(jJUHY) {" fullword ascii
    $s20 = "return FGO[CMSH[0]](zaGtJ);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}