rule sig_20160405_e00434f4e91aaa573570f13b365f7e8f {
  meta:
    description = "datamaliciousorder - file 20160405_e00434f4e91aaa573570f13b365f7e8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "407687144f519cc8088bc7d3df1234fb1223b92e806764dc9c12cc58ffeef21c"

  strings:
    $s1  = "return LBuSdRr[0] + LBuSdRr[2] + LBuSdRr[4] + \".F\" + LBuSdRr[7] + LBuSdRr[9] + LBuSdRr[12] + LBuSdRr[14];" fullword ascii
    $s2  = "var JQ = true  , hEtm = Ubj[7] + Ubj[9] + Ubj[11];" fullword ascii
    $s3  = "qnRk.open(TWsoD,wVSOB,false);" fullword ascii
    $s4  = "var Ubj = (\"2.XMLHTTP dRqnFKy ZhoDU XML ream St WyGkHgFO AD WuMPouj O pram D\").split(\" \");" fullword ascii
    $s5  = "function FYUJnua(JSZq,CsnLZ) {" fullword ascii
    $s6  = "return obPesaw;" fullword ascii
    $s7  = "if(Y>=i.length) {break;}" fullword ascii
    $s8  = "function PfMv(vAgzy) {" fullword ascii
    $s9  = "function pLWH(ubFOZ,pwBZi) {" fullword ascii
    $s10 = "function WBqyl(FezfWAkS,bwfV) {" fullword ascii
    $s11 = "return RrfF[AuWgNU[0]];" fullword ascii
    $s12 = "function hbxmFfNyH(FBcRnHTDtDU) {" fullword ascii
    $s13 = "function QRbKO(rkFtQz) {" fullword ascii
    $s14 = "return \"QOfjmstmmynMAD\";" fullword ascii
    $s15 = "function LbVYU(PEN,jQkvB) {" fullword ascii
    $s16 = "return Jvl.size;" fullword ascii
    $s17 = "return jIDBQ;" fullword ascii
    $s18 = "function qLelKuVR(DTZp) {" fullword ascii
    $s19 = "function irSV(adcmK) {" fullword ascii
    $s20 = "return FYUJnua(QU,wuxVL[999-993]+wuxVL[679-672]+wuxVL[417-409]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}