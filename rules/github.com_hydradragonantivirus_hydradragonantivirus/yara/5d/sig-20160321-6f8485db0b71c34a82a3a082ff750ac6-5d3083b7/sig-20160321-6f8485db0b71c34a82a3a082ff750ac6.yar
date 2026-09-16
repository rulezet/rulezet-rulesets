rule sig_20160321_6f8485db0b71c34a82a3a082ff750ac6 {
  meta:
    description = "datamaliciousorder - file 20160321_6f8485db0b71c34a82a3a082ff750ac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "292e2dc1e865bbb5877afea28f12ef160db8d5cd99f481826976b28b351bbfe2"

  strings:
    $s1  = "return WScript.CreateObject(OkbDD);" fullword ascii
    $s2  = "return FHdlICi[0] + FHdlICi[2] + FHdlICi[4] + \".F\" + FHdlICi[7] + FHdlICi[9] + FHdlICi[12] + FHdlICi[14];" fullword ascii
    $s3  = "var oy = true  , qhqi = aEn[7] + aEn[9] + aEn[11];" fullword ascii
    $s4  = "JlLye.open(DYLrS,bgRjS,false);" fullword ascii
    $s5  = "var FHdlICi = SUoOc(eUIrnDudNK+\" \"+\"System ce KFhLT Obj clmGAY ect ZMDZcip XYdwD\", \" \");" fullword ascii
    $s6  = "var aEn = (\"2.XMLHTTP ZYiBdBz yVcIb XML ream St eIwjFcXl AD bRVOrFF O MJlT D\").split(\" \");" fullword ascii
    $s7  = "function uyRUNfDwr(UFfDhCqCwRG) {" fullword ascii
    $s8  = "if(W>=r.length) {break;}" fullword ascii
    $s9  = "return kzhH[cDeZgg[0]];" fullword ascii
    $s10 = "return QaMTe.status;" fullword ascii
    $s11 = "function vRajWFeBM(BqKhK) {" fullword ascii
    $s12 = "function fVnf(OkbDD) {" fullword ascii
    $s13 = "return BZKMe;" fullword ascii
    $s14 = "function eYSm(QaMTe) {" fullword ascii
    $s15 = "Nxb = W; break; " fullword ascii
    $s16 = "return hULY.ExpandEnvironmentStrings(IRomt);" fullword ascii
    $s17 = "function SUoOc(eMu,oDOuO) {" fullword ascii
    $s18 = "function NvQB(cLkpG,yetdN) {" fullword ascii
    $s19 = "return new ActiveXObject(ETtZxV);" fullword ascii
    $s20 = "function psZuoWaf(VMbA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}