rule sig_20160312_1e6c6e0f7981388800696a643009e9f4 {
  meta:
    description = "datamaliciousorder - file 20160312_1e6c6e0f7981388800696a643009e9f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eead1707c8a3447af36f3e87091f6fc83baa60772efe4e90c02caf0ddd185658"

  strings:
    $s1  = "var EW = true  , wBtb = IKd[7] + IKd[9] + IKd[11];" fullword ascii
    $s2  = "return gDxfNxG[0] + gDxfNxG[2] + gDxfNxG[4] + \".F\" + gDxfNxG[7] + gDxfNxG[9] + gDxfNxG[12] + gDxfNxG[14];" fullword ascii
    $s3  = "sGjed.open(rcqte,pLAkS,false);" fullword ascii
    $s4  = "var IKd = (\"2.XMLHTTP YPXcjPJ qPOlv XML ream St KBoOqeKC AD iNkeFtg O rMzF D\").split(\" \");" fullword ascii
    $s5  = "if(H>=h.length) {break;}" fullword ascii
    $s6  = "function MgUdQeB(pGMv) {" fullword ascii
    $s7  = "return new ActiveXObject(kTuKdp);" fullword ascii
    $s8  = "function Iqpv(KMbhT,mvyRQ) {" fullword ascii
    $s9  = "if (vdcXT == 897-697){return true;} else {return false;}" fullword ascii
    $s10 = "return uaSZ.ExpandEnvironmentStrings(kwoff);" fullword ascii
    $s11 = "return THXLl.status;" fullword ascii
    $s12 = "function TtYZD(kZQkMb) {" fullword ascii
    $s13 = "function mqWK(vdcXT) {" fullword ascii
    $s14 = "return QfS.size;" fullword ascii
    $s15 = "if (ZDYhJ > 160416-476){return true;} else {return false;}" fullword ascii
    $s16 = "function CfTYVOLYh(FvGgVgIbUiV) {" fullword ascii
    $s17 = "function aANq(MJtVy) {" fullword ascii
    $s18 = "if (U >= xeBbS.length) {break;}" fullword ascii
    $s19 = "function JqRrwqCJ(QfS) {" fullword ascii
    $s20 = "function TDnp(sGjed,pLAkS,rcqte) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}