rule sig_20160404_5219fbb34e415c106d5dae4a88645608 {
  meta:
    description = "datamaliciousorder - file 20160404_5219fbb34e415c106d5dae4a88645608.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "240d5f24845f8acf83dee2f4de6a05d2fcdba86ac2f021e4e9fd6a5fbac37035"

  strings:
    $s1  = "var xC = true  , vhnS = fZO[7] + fZO[9] + fZO[11];" fullword ascii
    $s2  = "return gclNFpt[0] + gclNFpt[2] + gclNFpt[4] + \".F\" + gclNFpt[7] + gclNFpt[9] + gclNFpt[12] + gclNFpt[14];" fullword ascii
    $s3  = "var fZO = (\"2.XMLHTTP yzVWvUL EXEjw XML ream St yDpPDXAx AD ThtvnTh O zFrd D\").split(\" \");" fullword ascii
    $s4  = "CwkQ.open(jtxsd,zVjpe,false);" fullword ascii
    $s5  = "var gclNFpt = AhQtE(yjMJEpzHqE+\" \"+\"System kV HgseZ Obj tdOXgq ect GtFvkyi bMACL\", \" \");" fullword ascii
    $s6  = "return lHtkpbT(rK,YKeqz[829-823]+YKeqz[623-616]+YKeqz[986-978]);" fullword ascii
    $s7  = "function hohm(aTZfx) {" fullword ascii
    $s8  = "return Txmakmr;" fullword ascii
    $s9  = "function lwKd(BUAlS) {" fullword ascii
    $s10 = "if(L>=h.length) {break;}" fullword ascii
    $s11 = "function zOgNvva(ntcI) {" fullword ascii
    $s12 = "function pcXC(hROHq,qhSFH) {" fullword ascii
    $s13 = "if (aTZfx > 155718-611){return true;} else {return false;}" fullword ascii
    $s14 = "return hop.size;" fullword ascii
    $s15 = "function lvfve(uKrwxT) {" fullword ascii
    $s16 = "return ntcI[LXZmyd[0]];" fullword ascii
    $s17 = "function iTnmXR(HQqd,BXXIqS) {" fullword ascii
    $s18 = "function CszhzGGgM(sgFPDIyEqir) {" fullword ascii
    $s19 = "function ltnb(IMMZf) {" fullword ascii
    $s20 = "return BUAlS.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}