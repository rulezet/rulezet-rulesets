rule sig_20160324_369adce385f3690b2a1d2ac15cc5e215 {
  meta:
    description = "datamaliciousorder - file 20160324_369adce385f3690b2a1d2ac15cc5e215.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7b698b10b8a7467a633458f88296cf376def9889418528c32e542ef979a52e"

  strings:
    $s1  = "return WScript.CreateObject(ObNOo);" fullword ascii
    $s2  = "return AXZEUJK[0] + AXZEUJK[2] + AXZEUJK[4] + \".F\" + AXZEUJK[7] + AXZEUJK[9] + AXZEUJK[12] + AXZEUJK[14];" fullword ascii
    $s3  = "var JT = true  , QcSk = yDa[7] + yDa[9] + yDa[11];" fullword ascii
    $s4  = "ZsIT.open(TThCU,VwBrO,false);" fullword ascii
    $s5  = "var AXZEUJK = KlqzM(xzQbIKvICW+\" \"+\"System Gr agzws Obj iNtJGR ect vwJeEEM CsGoR\", \" \");" fullword ascii
    $s6  = "var yDa = (\"2.XMLHTTP uzyjjFm MmVlb XML ream St QjcMRJvX AD asvIbgm O ydFA D\").split(\" \");" fullword ascii
    $s7  = "function JNBl(ObNOo) {" fullword ascii
    $s8  = "function aiApyWWd(VvYX) {" fullword ascii
    $s9  = "function zXhiDzpPr(XEYxoXgyHCh) {" fullword ascii
    $s10 = "function mudxYqA(XEqo,FxxlR) {" fullword ascii
    $s11 = "function BVyc(goKmW,tgpJB) {" fullword ascii
    $s12 = "return XEqo.ExpandEnvironmentStrings(FxxlR);" fullword ascii
    $s13 = "return KKSU[dWdmWP[0]];" fullword ascii
    $s14 = "if (fLgrl > 172939-750){return true;} else {return false;}" fullword ascii
    $s15 = "KZP = Y; break; " fullword ascii
    $s16 = "function wtst(Lghoi) {" fullword ascii
    $s17 = "function ZVzq(ouyhp) {" fullword ascii
    $s18 = "return mudxYqA(oP,LvDDi[734-728]+LvDDi[974-967]+LvDDi[402-394]);" fullword ascii
    $s19 = "return lPqzS;" fullword ascii
    $s20 = "return ouyhp.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}