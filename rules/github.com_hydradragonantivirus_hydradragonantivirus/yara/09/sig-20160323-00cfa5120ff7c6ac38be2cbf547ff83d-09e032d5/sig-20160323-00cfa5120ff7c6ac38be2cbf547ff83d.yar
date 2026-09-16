rule sig_20160323_00cfa5120ff7c6ac38be2cbf547ff83d {
  meta:
    description = "datamaliciousorder - file 20160323_00cfa5120ff7c6ac38be2cbf547ff83d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa4c49b42509bb22fbd98d5ae95fb8c4436cd1588b176b5dcf8daeb5ed7b53f6"

  strings:
    $s1  = "return WScript.CreateObject(IVjPF);" fullword ascii
    $s2  = "return GZRihrU[0] + GZRihrU[2] + GZRihrU[4] + \".F\" + GZRihrU[7] + GZRihrU[9] + GZRihrU[12] + GZRihrU[14];" fullword ascii
    $s3  = "var Lz = true  , cBWL = gqx[7] + gqx[9] + gqx[11];" fullword ascii
    $s4  = "var GZRihrU = DqRYE(OidhdLozJA+\" \"+\"System OW JCzbq Obj tRCtPR ect EZkCrVI wgqJs\", \" \");" fullword ascii
    $s5  = "NmTP.open(DisMN,unVPj,false);" fullword ascii
    $s6  = "var gqx = (\"2.XMLHTTP qHbyZHq bfxzm XML ream St BjUMXviz AD ZeIZslr O uQYK D\").split(\" \");" fullword ascii
    $s7  = "return VAu.split(Yhzys);" fullword ascii
    $s8  = "return OPv.size;" fullword ascii
    $s9  = "return OhDoZ.status;" fullword ascii
    $s10 = "function itOx(BuOzF,KoGKJ) {" fullword ascii
    $s11 = "if (JFSDW > 172824-727){return true;} else {return false;}" fullword ascii
    $s12 = "function eAgXSkdi(dJzA) {" fullword ascii
    $s13 = "return JycpPGF(Hu,QFjSm[191-185]+QFjSm[363-356]+QFjSm[195-187]);" fullword ascii
    $s14 = "function XlmK(bCkgI) {" fullword ascii
    $s15 = "function FKBd(OhDoZ) {" fullword ascii
    $s16 = "function ICUml(nQKhzV) {" fullword ascii
    $s17 = "return ylgY.ExpandEnvironmentStrings(pxSYs);" fullword ascii
    $s18 = "function lIaP(UXcJl,RhMZT) {" fullword ascii
    $s19 = "function DPwI(IVjPF) {" fullword ascii
    $s20 = "function aDdDfGkgP(NArlkOLBIOM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}