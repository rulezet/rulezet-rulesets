rule sig_20160310_fe9f19c8e6e42edcd99dd228656fdf96 {
  meta:
    description = "datamaliciousorder - file 20160310_fe9f19c8e6e42edcd99dd228656fdf96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aca90221469e2a63dfb65d61b7326283dab7d1557f47a6c24497abb675145a0d"

  strings:
    $s1  = "return IXHARKz[0] + IXHARKz[2] + IXHARKz[4] + \".F\" + IXHARKz[7] + IXHARKz[9] + IXHARKz[12] + IXHARKz[14];" fullword ascii
    $s2  = "var wi = true  , wBoy = Mah[7] + Mah[9] + Mah[11];" fullword ascii
    $s3  = "var IXHARKz = \"Sc qjHkGGN r QeSxzZSai ipting EdUUgfw jPG ile OZeJFhzoQVbFOH System ou DhAct Obj LSfKnI ect sMRsuiW\".split(\" " ascii
    $s4  = "TFSHo.open(iLnjL,jCrxE,false);" fullword ascii
    $s5  = "var Mah = (\"2.XMLHTTP UexVvdz evhTt XML ream St jcldOnzN AD NHgpvft O BPwS D\").split(\" \");" fullword ascii
    $s6  = "function FUHMvnuz() {" fullword ascii
    $s7  = "function yIUp(CHDjV) {" fullword ascii
    $s8  = "return tzsSug.position=131-131;" fullword ascii
    $s9  = "return HyhYl;" fullword ascii
    $s10 = "function sejGYdtdl(pjBpL,edFCz,QGyso,RGsV) {" fullword ascii
    $s11 = "Jhg = U; break; " fullword ascii
    $s12 = "function lMrH(qDnDV) {" fullword ascii
    $s13 = "return mwlU.responseBody;" fullword ascii
    $s14 = "if (qDnDV == 802-602){return true;} else {return false;}" fullword ascii
    $s15 = "function FmwJrZfF(SveKf,cNpjde) {" fullword ascii
    $s16 = "function wdnA(zviya,MOYkq) {" fullword ascii
    $s17 = "return XeddG.status;" fullword ascii
    $s18 = "function KUgC(XeddG) {" fullword ascii
    $s19 = "function hwgNh(tzsSug) {" fullword ascii
    $s20 = "function bdpX(ZuSGV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}